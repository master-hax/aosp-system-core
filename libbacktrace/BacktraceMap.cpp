/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <backtrace/backtrace_constants.h>
#include <backtrace/BacktraceMap.h>

#include "BacktraceLog.h"
#include "BacktraceMapBasic.h"

BacktraceMap::BacktraceMap(pid_t pid) : pid_(pid) {
  if (pid_ < 0) {
    pid_ = getpid();
  }
}

#if defined(__APPLE__)
// Corkscrew and libunwind don't compile on the mac, so create a generic
// map object.
BacktraceMap* BacktraceMap::Create(pid_t pid, bool /*uncached*/) {
  BacktraceMap* map = new BacktraceMapBasic(pid);
  if (!map->Build()) {
    delete map;
    return nullptr;
  }
  return map;
}
#endif

BacktraceMap* BacktraceMap::Create(pid_t pid, const std::vector<backtrace_map_t>& maps) {
  return new BacktraceMapBasic(pid, maps);
}
