/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "BacktraceOffline.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include "BacktraceLog.h"
#include "UnwindStack.h"
#include "UnwindStackMap.h"

void BacktraceOffline::SetArch(ArchEnum arch) {
  arch_ = arch;
}

BacktraceOffline::BacktraceOffline(pid_t pid, pid_t tid, BacktraceMap* map)
    : Backtrace(pid, tid, map) {}

Backtrace* Backtrace::CreateOffline(pid_t pid, pid_t tid, const std::vector<backtrace_map_t>& maps,
                                    const backtrace_stackinfo_t& stack) {
  BacktraceMap* map = BacktraceMap::CreateOffline(pid, maps, stack);
  if (map == nullptr) {
    return nullptr;
  }

  return new UnwindStackOffline(pid, tid, map, false);
}

Backtrace* Backtrace::CreateOffline(pid_t pid, pid_t tid, BacktraceMap* map) {
  if (map == nullptr) {
    return nullptr;
  }
  return new UnwindStackOffline(pid, tid, map, true);
}
