/*
 * Copyright 2017, The Android Open Source Project
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

#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

// s is like 1,2,3
bool GetSignalList(const char* s, std::vector<int>& signals) {
  std::vector<std::string> strs = android::base::Split(s, ",");
  for (auto& a : strs) {
    int sig;
    if (!android::base::ParseInt(a, &sig, 0)) {
      return false;
    }
    signals.push_back(sig);
  }
  return true;
}

void RunChildProcess(char** child_argv) {
  ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
  execvp(child_argv[0], child_argv);
}

void DumpChildProcCallChain(int child_pid) {
  printf("dump call chain of process %d\n", child_pid);
  std::unique_ptr<BacktraceMap> map(BacktraceMap::Create(child_pid));
  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(child_pid, child_pid, map.get()));
  backtrace->Unwind(0);
  printf("backtrace count = %zu\n", backtrace->NumFrames());
  for (auto it = backtrace->begin(); it != backtrace->end(); ++it) {
    printf("--%s[+0x%" PRIx64 "]\n", it->func_name.c_str(), static_cast<uint64_t>(it->func_offset));
  }
}

bool TraceChildProcess(int child_pid, const std::vector<int>& wait_signals) {
  int status;
  while (true) {
    int ret = TEMP_FAILURE_RETRY(waitpid(child_pid, &status, 0));
    if (ret < 0) {
      PLOG(ERROR) << "waitpid failed";
      return false;
    }
    if (WIFEXITED(status)) {
      printf("child process exited with code %d\n", WEXITSTATUS(status));
      return true;
    }
    if (WIFSIGNALED(status)) {
      printf("child process was terminated by signal %s\n", strsignal(WTERMSIG(status)));
      return true;
    }
    if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      bool traced = false;
      for (int s : wait_signals) {
        if (s == sig) {
          traced = true;
          break;
        }
      }
      if (traced) {
        printf("child process was stopped by delivery of signal %s\n", strsignal(sig));
        DumpChildProcCallChain(child_pid);
      }
      if (sig == SIGTRAP) {
        sig = 0;
      }
      ptrace(PTRACE_CONT, child_pid, nullptr, reinterpret_cast<void*>(static_cast<intptr_t>(sig)));
    }
  }
}

void usage(char* argv0) {
  char* prog_name = basename(argv0);
  printf("%s - print callchain when segment fault happens in sub process.\n", prog_name);
  printf("usage: %s [options] commands...\n", prog_name);
  printf("  commands are used to run in sub process. options are as below:\n");
  printf("  -h                Print this help message.\n");
  printf("  -s sig1,sig2,...  Set tracing signal numbers.\n");
  printf("                    By default it is 6,11 (6 is SIGABORT, 11 is SIGSEGV).\n");
  printf("  --show-example    Show a SIGSEGV catching example.\n");
  exit(0);
}

int main(int argc, char** argv) {
  android::base::InitLogging(argv, android::base::StderrLogger);
  std::vector<int> signals = {6, 11};
  bool show_example = false;
  bool run_segfault_function = false;
  int i;
  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
    } else if (strcmp(argv[i], "-s") == 0) {
      if (i + 1 == argc) {
        LOG(ERROR) << "no argument for -s.\n";
        return 1;
      }
      signals.clear();
      if (!GetSignalList(argv[i + 1], signals)) {
        LOG(ERROR) << "wrong argument for -s: " << argv[i + 1];
        return 1;
      }
      i++;
    } else if (strcmp(argv[i], "--show-example") == 0) {
      show_example = true;
    } else if (strcmp(argv[i], "--run-segfault-function") == 0) {
      run_segfault_function = true;
    } else {
      LOG(ERROR) << "unknown option: " << argv[i];
    }
  }

  if (run_segfault_function) {
    volatile int* p = reinterpret_cast<int*>(static_cast<intptr_t>(atoi("1")));
    printf("won't reach %d\n", *p);
    return 0;
  }
  char** child_argv = nullptr;
  char* show_example_argv[3];
  if (show_example) {
    show_example_argv[0] = argv[0];
    show_example_argv[1] = const_cast<char*>("--run-segfault-function");
    show_example_argv[2] = nullptr;
    child_argv = show_example_argv;
  } else {
    if (i == argc) {
      LOG(ERROR) << "no command for sub process";
      return 1;
    }
    child_argv = argv + i;
  }

  int child = fork();
  if (child == 0) {
    RunChildProcess(child_argv);
  } else if (child > 0) {
    TraceChildProcess(child, signals);
  } else {
    PLOG(ERROR) << "fork failed";
    return 1;
  }
  return 0;
}
