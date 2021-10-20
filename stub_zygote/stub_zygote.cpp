/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <signal.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <cutils/sockets.h>

using android::base::borrowed_fd;
using android::base::unique_fd;

static std::vector<const char*> zygote_args [[clang::no_destroy]];
static std::vector<const char*> zygote_environ [[clang::no_destroy]];
static std::string zygote_socket [[clang::no_destroy]] = "zygote_secondary";
static std::string intermediate_socket [[clang::no_destroy]] = "stub_zygote";

// Read a line if possible, consuming it from the buffer.
static std::optional<std::string_view> ReadLine(std::string_view& buffer) {
  auto offset = buffer.find('\n');
  if (offset == std::string_view::npos) {
    return {};
  }

  std::string_view result(buffer.begin(), offset + 1);
  buffer.remove_prefix(result.size());
  return result;
}

static std::optional<std::vector<char>> ParseRequest(std::vector<char>& buffer) {
  // zygote requests are awful to parse: we get a number of lines (in ASCII), followed by
  // that many lines of text. It's not guaranteed to get this in one read, so we need to buffer.
  std::string_view data(&buffer[0], buffer.size());
  auto line_count_str = ReadLine(data);
  if (!line_count_str) {
    LOG(ERROR) << "failed to read line count?";
    return {};
  }

  // Remove the trailing newline to feed to ParseUint.
  line_count_str->remove_suffix(1);

  unsigned int line_count;
  if (!android::base::ParseUint(std::string(*line_count_str), &line_count)) {
    LOG(FATAL) << "failed to parse request line count: '" << *line_count_str << "'";
  }

  auto end = data.end();
  for (unsigned int i = 0; i < line_count; ++i) {
    auto line = ReadLine(data);
    if (!line) {
      // Out of lines, try again with more data.
      return {};
    }
    end = line->end();
  }

  size_t request_length = end - &buffer[0];
  auto buffer_end = buffer.begin() + request_length;
  std::vector<char> result(buffer.begin(), buffer_end);
  buffer.erase(buffer.begin(), buffer_end);
  return result;
}

static void BlockSigchld() {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &set, nullptr) != 0) {
    PLOG(FATAL) << "failed to block SIGCHLD";
  }
}

static void UnblockSigchld() {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  if (sigprocmask(SIG_UNBLOCK, &set, nullptr) != 0) {
    PLOG(FATAL) << "failed to unblock SIGCHLD";
  }
}

static void SigchldHandler(int) {
  int status;
  pid_t pid;
  while ((pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, WNOHANG))) > 0) {
    if (WIFEXITED(status)) {
      async_safe_format_log(ANDROID_LOG_INFO, "stub_zygote", "Process %d exited cleanly (%d)", pid,
                            WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
      async_safe_format_log(ANDROID_LOG_INFO, "stub_zygote",
                            "Process %d exited due to signal %d (%s)%s", pid, WTERMSIG(status),
                            strsignal(WTERMSIG(status)), WCOREDUMP(status) ? "; core dumped" : "");
    }
  }

  // Don't log failure: it'll happen every time we spawn a zygote, since we
  // waitpid with SIGCHLD blocked, and then unblock SIGCHLD.
}

// Spawn a zygote and send it a request.
static void SpawnZygote(borrowed_fd request_fd, std::vector<char> request) {
  // Block signals before forking, so that the SIGCHLD handler doesn't steal our waitpid.
  BlockSigchld();
  pid_t forkpid = fork();
  if (forkpid == -1) {
    PLOG(FATAL) << "fork failed";
  } else if (forkpid == 0) {
    // Child.
    UnblockSigchld();
    execve(zygote_args[0], const_cast<char**>(zygote_args.data()),
           const_cast<char**>(zygote_environ.data()));
    PLOG(FATAL) << "execve failed";
  }

  // Parent.
  unique_fd client(socket(AF_UNIX, SOCK_STREAM, 0));
  if (client == -1) {
    PLOG(FATAL) << "failed to create client socket";
  }

  if (socket_local_client_connect(client.get(), intermediate_socket.c_str(),
                                  ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM) == -1) {
    PLOG(FATAL) << "failed to connect to intermediate socket";
  } else {
    if (!android::base::WriteFully(client.get(), request.data(), request.size())) {
      PLOG(ERROR) << "failed to write request";
    }

    ssize_t rc;
    char buf[PIPE_BUF];
    while ((rc = TEMP_FAILURE_RETRY(read(client.get(), buf, sizeof(buf)))) != 0) {
      if (rc == -1) {
        PLOG(FATAL) << "error while reading zygote response";
      }

      if (!android::base::WriteFully(request_fd.get(), buf, rc)) {
        PLOG(ERROR) << "failed to write response to client";
        break;
      }
    }
  }

  pid_t pid = TEMP_FAILURE_RETRY(waitpid(forkpid, nullptr, 0));
  if (pid == -1) {
    PLOG(FATAL) << "waitpid failed";
  }
  CHECK_EQ(forkpid, pid);
  UnblockSigchld();
}

int main(int argc, const char** argv) {
  // system_server expects to have a long lasting connection to the zygote,
  // so we listen on the socket and spawn zygotes that listen to an intermediate
  // socket that we forward requests to.
  int zygote_fd = android_get_control_socket(zygote_socket.c_str());
  if (zygote_fd == -1) {
    PLOG(FATAL) << "failed to get control socket: " << zygote_socket;
  }

  if (fcntl(zygote_fd, F_SETFD, FD_CLOEXEC) == -1) {
    PLOG(FATAL) << "failed to set FD_CLOEXEC flag on zygote socket";
  }

  int intermediate_fd = android_get_control_socket(intermediate_socket.c_str());
  if (intermediate_fd == -1) {
    PLOG(FATAL) << "stub_zygote intermediate socket not found";
  }

  // listen on the intermediate socket, so that we block while waiting for the zygote to accept.
  if (listen(intermediate_fd, 1) != 0) {
    PLOG(FATAL) << "failed to listen on intermediate socket";
  }

  // Initialize zygote argv.
  for (int i = 1; i < argc; ++i) {
    // There's a --socket-name argument, but it's not used by the zygote directly for some reason.
    // The zygote checks if it equals "zygote", and if not, it uses "zygote_secondary".
    // Assume that we're always going to be zygote_secondary.
    zygote_args.push_back(argv[i]);
  }
  zyygote_args.push_back("--oneshot");
  zyygote_args.push_back(nullptr);

  // Initialize zygote environment variables.
  for (char** env_p = environ; *env_p != nullptr; ++env_p) {
    std::string_view env = *env_p;
    if (env.starts_with("ANDROID_SOCKET_stub_zygote=")) {
      continue;
    } else if (env.starts_with("ANDROID_SOCKET_zygote_secondary=")) {
      static std::string zygote_env_arg [[clang::no_destroy]] =
          android::base::StringPrintf("ANDROID_SOCKET_zygote_secondary=%d", intermediate_fd);
      zygote_environ.push_back(zygote_env_arg.c_str());
    } else {
      zygote_environ.push_back(*env_p);
    }
  }
  zygote_environ.push_back(nullptr);

  // Set ourselves as a child subreaper, so children of the oneshot zygote get reparented onto us.
  if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
    PLOG(FATAL) << "failed to set PR_SET_CHILD_SUBREAPER";
  }

  // Register a SIGCHLD handler to reap our inherited children.
  struct sigaction sigchld_handler = {
      .sa_handler = SigchldHandler,
      .sa_flags = SA_NOCLDSTOP,
  };
  if (sigaction(SIGCHLD, &sigchld_handler, nullptr) != 0) {
    PLOG(FATAL) << "failed to register SIGCHLD handler";
  }

  android::base::unique_fd epfd(epoll_create1(EPOLL_CLOEXEC));
  if (epfd == -1) {
    PLOG(FATAL) << "failed to create epoll fd";
  }

  {
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = zygote_fd;

    if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, zygote_fd, &event) != 0) {
      PLOG(FATAL) << "failed to register epoll fd";
    }
  }

  struct ZygoteConnection {
    unique_fd fd;
    std::vector<char> buffer;
  };

  std::unordered_map<int, ZygoteConnection> clients;

  if (listen(zygote_fd, 128) != 0) {
    PLOG(FATAL) << "failed to listen on zygote socket";
  }

  while (true) {
    struct epoll_event events[2];
    int rc = TEMP_FAILURE_RETRY(epoll_wait(epfd.get(), events, std::size(events), -1));
    if (rc == -1) {
      PLOG(FATAL) << "epoll_wait failed";
    } else if (rc == 0) {
      PLOG(FATAL) << "epoll_wait returned zero events";
    }

    for (int i = 0; i < rc; ++i) {
      if (events[i].data.fd == zygote_fd) {
        unique_fd client(accept4(zygote_fd, nullptr, nullptr, SOCK_CLOEXEC));
        if (client == -1) {
          PLOG(FATAL) << "failed to accept client";
        }

        int client_fd = client.get();

        struct epoll_event event;
        event.events = EPOLLIN;
        event.data.fd = client_fd;

        if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, client_fd, &event) == -1) {
          PLOG(FATAL) << "failed to add client fd to epoll";
        }

        LOG(DEBUG) << "received new client: fd = " << client_fd;
        clients[client_fd] = {
            .fd = std::move(client),
        };
      } else {
        auto it = clients.find(events[i].data.fd);
        if (it == clients.end()) {
          LOG(FATAL) << "received epoll event for unknown fd: " << events[i].data.fd;
        }

        char buf[PIPE_BUF];
        ssize_t read_bytes = TEMP_FAILURE_RETRY(read(events[i].data.fd, buf, sizeof(buf)));
        if (read_bytes == -1) {
          PLOG(FATAL) << "failed to read from client";
        } else if (read_bytes == 0) {
          LOG(DEBUG) << "client connection terminated: fd = " << events[i].data.fd;
          if (epoll_ctl(epfd.get(), EPOLL_CTL_DEL, events[i].data.fd, nullptr) != 0) {
            PLOG(FATAL) << "failed to remove client fd from epoll";
          }
          clients.erase(it);
          continue;
        }

        it->second.buffer.insert(it->second.buffer.end(), buf, buf + read_bytes);

        std::optional<std::vector<char>> request = ParseRequest(it->second.buffer);
        if (request) {
          LOG(DEBUG) << "spawning zygote for request: fd = " << it->first;
          SpawnZygote(it->first, std::move(*request));
        } else {
          LOG(VERBOSE) << "received partial request: fd = " << it->first;
        }
      }
    }
  }
}
