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

#ifndef ANDROID_BASE_FORK_H
#define ANDROID_BASE_FORK_H

#include <functional>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace android {
namespace base {

// Executes the provided function in a fork()ed child process.
//
// The child function must return an int, which will be used as the child
// process's exit status.
template <class... Args>
class fork_helper {
 public:
  fork_helper(std::function<int(Args...)>&& f, Args&&... args)
      : child_pid{fork()} {
    if (child_pid == 0) _exit(f(args...));
  }

  // Returns whether the fork succeeded.
  operator bool() const { return child_pid != -1; }
  // Returns the child's PID.
  pid_t pid() const { return child_pid; }

  // Kills the child process with the specified signal, returning whether or
  // not it succeeded.
  bool kill(int sig = SIGKILL) {
    auto err = ::kill(child_pid, sig);
    if (err < 0) return false;

    int s;
    auto p = waitpid(child_pid, &s, 0);
    return p == child_pid && WIFSIGNALED(s) && WTERMSIG(s) == sig;
  }

  // Waits for the child process to exit, returning whether or not it
  // successfully exited with the expected status code.
  bool wait(int status = 0) {
    int s;
    auto p = waitpid(child_pid, &s, 0);
    return p == child_pid && WIFEXITED(s) && WEXITSTATUS(s) == status;
  }

 private:
  const pid_t child_pid;
};

};  // namespace base
};  // namespace android

#endif  // ANDROID_BASE_FORK_H
