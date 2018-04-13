/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "android-base/process.h"

#include <sys/wait.h>

#include "android-base/logging.h"
#include "android-base/macros.h"

namespace android {
namespace base {

//
// ExitStatus.
//

ExitStatus::ExitStatus(int status) : status_(status) {}

bool ExitStatus::DidExit() {
  return WIFEXITED(status_);
}

int ExitStatus::ExitValue() {
  return WEXITSTATUS(status_);
}

bool ExitStatus::WasSignaled() {
  return WIFSIGNALED(status_);
}

int ExitStatus::Signal() {
  return WTERMSIG(status_);
}

//
// Process.
//

Process::Process(pid_t pid) : pid_(pid), waited_(false), status_(0) {}

pid_t Process::GetPid() {
  return pid_;
}

bool Process::Kill(int signal) {
  return (kill(pid_, signal) == 0);
}

bool Process::WaitFor() {
  if (TEMP_FAILURE_RETRY(waitpid(pid_, &status_, 0)) == pid_) waited_ = true;
  return waited_;
}

ExitStatus Process::GetExitStatus() {
  // TODO: throw if !waited_?
  return ExitStatus{status_};
}

//
// ProcessBuilder.
//

ProcessBuilder::ProcessBuilder(std::initializer_list<std::string> args) : args_(args) {}

// TODO: Win32 implementation with CreateProcess

Process ProcessBuilder::Start() {
  pid_t pid = fork();
  if (pid == -1) {
    PLOG(ERROR) << "fork failed";
    return Process{-1};  // TODO: throw?
  }

  if (pid == 0) {
    // Child.
    std::vector<const char*> argv;
    for (const auto& arg : args_) argv.push_back(arg.c_str());
    argv.push_back(nullptr);

    execvp(argv[0], const_cast<char**>(argv.data()));
    PLOG(ERROR) << "execvp failed";
    _exit(127);
  }

  return Process{pid};
}

ExitStatus ProcessBuilder::RunAndWait() {
  Process p = Start();
  if (p.GetPid() == -1) return ExitStatus{1};  // TODO: throw?

  if (!p.WaitFor()) return ExitStatus{1};  // TODO: throw?

  return p.GetExitStatus();
}

}  // namespace base
}  // namespace android
