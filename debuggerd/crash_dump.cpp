/*
 * Copyright 2016, The Android Open Source Project
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

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include <memory>
#include <vector>

#include <log/logger.h>

#include "signal_sender.h"
#include "backtrace.h"
#include "tombstone.h"
#include "utility.h"

int main(int argc, char** argv) {
  if (argc == 1) {
    return 1;
  }

  std::vector<pid_t> tids;
  for (size_t i = 1; i < static_cast<size_t>(argc); ++i) {
    errno = 0;
    long tid = strtol(argv[i], nullptr, 10);
    if (errno != 0 || tid < 0) {
      fprintf(stderr, "crash_dump: invalid tid '%s'", argv[i]);
      exit(1);
    }

    tids.push_back(atoi(argv[i]));
  }

  ALOGE("crash_dump: performing dump on tid %d", tids[0]);
  // At this point, the thread that made the request has been PTRACE_ATTACHed
  // and has the signal that triggered things queued. Send PTRACE_CONT, and
  // then wait for the signal.
  if (ptrace(PTRACE_CONT, tids[0], 0, 0) != 0){
    ALOGE("crash_dump: PTRACE_CONT failed: %s", strerror(errno));
    return false;
  }

  int signo = wait_for_signal(tids[0]);
  ALOGV("crash_dump: waitpid received signal %d", signo);

  std::unique_ptr<BacktraceMap> backtrace_map(BacktraceMap::Create(tids[0]));

  std::set<pid_t> siblings;
  for (size_t i = 1; i < tids.size(); ++i) {
    siblings.insert(tids[i]);
  }

  int crash_signal = (signo == DEBUGGER_SIGNAL) ? 0 : signo;
  engrave_tombstone(STDOUT_FILENO, backtrace_map.get(), getppid(), tids[0], siblings, 0, nullptr);

  for (pid_t tid : tids) {
    if (ptrace(PTRACE_DETACH, tid, 0, crash_signal) != 0) {
      ALOGE("crash_dump: ptrace detach from %d failed: %s", tid, strerror(errno));
    }
  }

  return 0;
}
