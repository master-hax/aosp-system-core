#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <limits>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <debuggerd/client.h>
#include <debuggerd/protocol.h>
#include <debuggerd/util.h>
#include <selinux/selinux.h>

using android::base::unique_fd;

static void usage(int exit_code) {
  fprintf(stderr, "usage: debuggerd [-b] PID\n");
  exit(exit_code);
}

static void send_signal(pid_t pid, bool backtrace) {
  sigval val;
  val.sival_int = backtrace;
  if (sigqueue(pid, DEBUGGER_SIGNAL, val) != 0) {
    err(1, "failed to send signal to pid %d", pid);
  }
}

static std::thread spawn_redirect_thread(unique_fd fd) {
  return std::thread([fd{ std::move(fd) }]() {
    while (true) {
      char buf[BUFSIZ];
      ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), buf, sizeof(buf)));
      if (rc <= 0) {
        return;
      }

      if (!android::base::WriteFully(STDOUT_FILENO, buf, rc)) {
        return;
      }
    }
  });
}

static bool Pipe(unique_fd* read, unique_fd* write) {
  int pipefds[2];
  if (pipe(pipefds) != 0) {
    return false;
  }
  read->reset(pipefds[0]);
  write->reset(pipefds[1]);
  return true;
}

int main(int argc, char* argv[]) {
  // If we were executed by system_server, immediately transition to debuggerd_system.
  security_context_t context;
  if (getcon(&context) == 0) {
    if (strcmp(context, "u:r:system_server:s0") == 0) {
      if (setcon("u:r:debuggerd_system:s0") != 0) {
        PLOG(FATAL) << "failed to setcon to debuggerd_system";
      }
    }
    freecon(context);
  }

  if (argc <= 1) usage(0);
  if (argc > 3) usage(1);
  if (argc == 3 && strcmp(argv[1], "-b") != 0) usage(1);
  pid_t pid;
  if (!android::base::ParseInt(argv[argc - 1], &pid, 1, std::numeric_limits<pid_t>::max())) {
    usage(1);
  }

  // TODO: Check to make sure that pid refers to a thread group leader.
  unique_fd piperead, pipewrite;

  if (!Pipe(&piperead, &pipewrite)) {
    err(1, "failed to create pipe");
  }

  std::thread redirect_thread = spawn_redirect_thread(std::move(piperead));

  // -b was passed, so intercept the output for that pid.
  unique_fd sockfd(socket_local_client(kTombstonedInterceptSocketName,
                                       ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (sockfd == -1) {
    err(1, "failed to contact tombstoned");
  }

  InterceptRequest req = {.pid = pid };
  if (send_fd(sockfd.get(), &req, sizeof(req), std::move(pipewrite)) != sizeof(req)) {
    err(1, "failed to send output fd to tombstoned");
  }

  bool backtrace = argc == 3;
  send_signal(pid, backtrace);

  InterceptResponse response;
  ssize_t rc = TEMP_FAILURE_RETRY(read(sockfd.get(), &response, sizeof(response)));
  if (rc == 0) {
    errx(1, "failed to read response from tombstoned: timeout reached?");
  } else if (rc != sizeof(response)) {
    errx(1, "received packet of unexpected length from tombstoned: expected %zu, received %zd",
         sizeof(response), rc);
  }

  if (response.success != 1) {
    err(1, "failed to intercept: %.*s", int(sizeof(response.error_message)), response.error_message);
  }

  redirect_thread.join();
  return 0;
}
