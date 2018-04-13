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
#include "android-base/stringprintf.h"

namespace android {
namespace base {

//
// Process.
//

Process::Process(pid_t pid) : pid_(pid) {}

pid_t Process::GetPid() {
  return pid_;
}

bool Process::Kill(int signal) {
  return (kill(pid_, signal) == 0);
}

int Process::WaitFor() {
  int status = 0;
  if (pid_ != -1 && TEMP_FAILURE_RETRY(waitpid(pid_, &status, 0)) == pid_) return status;
  return -1;
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

int ProcessBuilder::RunAndWait() {
  Process p = Start();
  if (p.GetPid() == -1) return -1;

  return p.WaitFor();
}

std::string ExitStatusToString(int status) {
  // TODO: win32?
  if (status == -1) {
    return android::base::StringPrintf("failed to launch: %s", strerror(errno));
  } else if (status == 0) {
    return "ran successfully";
  } else if (WIFSIGNALED(status)) {
    return android::base::StringPrintf("was killed by signal %d (%s)", WTERMSIG(status),
                                       strsignal(WTERMSIG(status)));
  } else if (WIFSTOPPED(status)) {
    return android::base::StringPrintf("was stopped by signal %d (%s)", WSTOPSIG(status),
                                       strsignal(WSTOPSIG(status)));
  } else {
    return android::base::StringPrintf("exited with status %d", WEXITSTATUS(status));
  }
}

}  // namespace base
}  // namespace android
