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

#pragma once

#include <string>
#include <vector>

namespace android {
namespace base {

// TODO: is this useful? or just return the raw int like the shell would?
class ExitStatus {
 public:
  explicit ExitStatus(int status);

  bool DidExit();
  int ExitValue();

  bool WasSignaled();
  int Signal();

 private:
  int status_;
};

class Process {
 public:
  explicit Process(pid_t pid);

  pid_t GetPid();

  bool Kill(int signal = 9);

  bool WaitFor();
  ExitStatus GetExitStatus();

 private:
  pid_t pid_;
  bool waited_;
  int status_;
};

class ProcessBuilder {
 public:
  ProcessBuilder(std::initializer_list<std::string> args);

  // TODO: setter to choose evecvpe/execve.

  // TODO: envp.

  // TODO: redirection?

  // TODO: run arbitrary lambdas after fork?

  // TODO: android_fork_execvp had an option to ignore SIGINT and SIGQUIT;
  // not 100% sure whether folks are using that meaningfully

  // TODO: some way to run a command and collect its stdout/stderr.

  // assume logwrapper functionality accessed by simply prefixing args with
  // logwrapper args. probably not enough users to warrant making that easier?

  Process Start();
  ExitStatus RunAndWait();

 private:
  std::vector<std::string> args_;
};

}  // namespace base
}  // namespace android
