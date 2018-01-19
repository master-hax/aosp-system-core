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

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <backtrace/Backtrace.h>

static bool Attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
    return false;
  }

  // Allow at least 1 second to attach properly.
  for (size_t i = 0; i < 1000; i++) {
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0) {
      return true;
    }
    usleep(1000);
  }
  printf("%d: Failed to stop.\n", pid);
  return false;
}

void DoUnwind(pid_t pid) {
  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, pid));
  if (backtrace.get() == nullptr) {
    printf("Cannot create Backtrace object.\n");
    return;
  }

  if (!backtrace->Unwind(0)) {
    printf("Cannot unwind.\n");
    return;
  }

  if (backtrace->NumFrames() == 0) {
    printf("No frames to dump.\n");
    return;
  }

  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    printf("%s\n", backtrace->FormatFrameData(i).c_str());
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: unwind <PID>\n");
    return 1;
  }

  pid_t pid = atoi(argv[1]);
  if (!Attach(pid)) {
    printf("Failed to attach to pid %d: %s\n", pid, strerror(errno));
    return 1;
  }

  DoUnwind(pid);

  ptrace(PTRACE_DETACH, pid, 0, 0);

  return 0;
}
