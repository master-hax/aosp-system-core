/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_BASE_MULTIPROCESS_H
#define ANDROID_BASE_MULTIPROCESS_H

#include <sys/types.h>
#include <sys/wait.h>
#include <cstddef>
#include <cstdlib>

#include <android-base/unique_fd.h>
#include <cutils/compiler.h>

namespace android {
namespace base {

// A unique_fd-style wrapper around socketpair(2).
class unique_socketpair {
 public:
  unique_socketpair();
  ~unique_socketpair() {}

  unique_socketpair(const unique_socketpair &) = delete;
  unique_socketpair &operator=(const unique_socketpair &) = delete;

  // Returns whether socketpair() succeded.
  operator bool() const { return ok; }

  // Gets one of the fds without transfering ownership.
  int get(unsigned int i) const { return sp[i].get(); }
  // Gets one of the fds, and transfers ownership to the caller.
  int release(unsigned int i) { return sp[i].release(); }

 private:
  unique_fd sp[2];
  bool ok;
};

// Wraps fork() with simple helpers for common operations.
class fork_helper {
 public:
  fork_helper() : pid{::fork()} {}

  // Returns whether the fork succeeded.
  operator bool() const { return pid != -1; }
  // Returns the child's PID.
  pid_t child_pid() const { return pid; }
  // Returns whether this process is the parent.
  bool is_parent() const { return pid > 0; }

  // Kills the child process with the specific signal, returning whether or
  // not it succeeded.
  bool kill_child(int sig = SIGKILL);
  // Waits for the child process to exit, returning whether or not it
  // succesfully exited with the expected status code.
  bool wait_for_child(int status = 0);

 private:
  const pid_t pid;
};

// Wraps a local socket in a stream-style interface.
//
// Note that this is a thin wrapper around sendmsg() and recvmsg(), so
// there is no built-in error-checking to make sure the remote ends are sending
// and receiving the same kind of object.
//
// When sending or receiving an android::base::unique_fd, local_socketstream
// uses cmsg(3) with SCM_RIGHTS to share the fd between the processes.
class local_socketstream {
 public:
  local_socketstream(int fd = -1);
  // Claims the appropriate fd from the socketpair for the current process
  local_socketstream(unique_socketpair &sp, const fork_helper &f);
  ~local_socketstream() {}

  local_socketstream(const local_socketstream &) = delete;
  local_socketstream &operator=(const local_socketstream &) = delete;

  void reset(int fd) { sock.reset(fd); }

  // Returns false if an error has occurred, or true otherwise.
  operator bool() const { return ok; }

  // Sends a bitwise copy of val to the recipient.
  template <typename T>
  local_socketstream &operator<<(const T &val) {
    send_cmsg(&val, sizeof(val), -1);
    return *this;
  }

  // Receives a message from the sender, storing the output in val.
  template <typename T>
  local_socketstream &operator>>(T &val) {
    recv_cmsg(&val, sizeof(val), nullptr);
    return *this;
  }

  // Shares an fd with the recipient.
  local_socketstream &operator<<(const unique_fd &val);
  // Receives a shared fd from the sender.
  local_socketstream &operator>>(unique_fd &val);

 private:
  void send_cmsg(const void *buf, std::size_t size, int fd);
  void recv_cmsg(void *buf, std::size_t size, int *fd);

  unique_fd sock;
  bool ok;
};

};  // namespace base
};  // namespace android

#endif  // ANDROID_BASE_MULTIPROCESS_H
