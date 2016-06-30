/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <backtrace/BacktraceMap.h>

#include "UnwindStackMap.h"

//-------------------------------------------------------------------------
UnwindStackMap::UnwindStackMap(pid_t pid) : BacktraceMap(pid) {}

bool UnwindStackMap::Build() {
  if (pid_ == 0) {
    pid_ = getpid();
    maps.reset(new LocalMaps);
  } else {
    maps.reset(new RemoteMaps(pid));
  }

  // Iterate through the maps and fill in the backtrace_map_t structure.
  for (auto& map_info : maps) {
    backtrace_map_t map;
    map.start = map_info.start;
    map.end = map_info.end;
    map.offset = map_info.offset;
    // Always set to zero, I think that I should remove this field at some point.
    map.load_base = 0;
    map.flags = map_info.flags;
    map.name = map_info.name;

    maps_.push_back(map);
  }

  return true;
}

void UnwindStackMap::FillIn(uintptr_t addr, backtrace_map_t* map) {
  BacktraceMap::FillIn(addr, map);
  if (map->load_bias != 0) {
    return;
  }

  // Fill in the load_bias.
  MapInfo* map_info = maps_->Find(addr);
  Elf* elf = map_info->GetElf(Pid(), true);
  if (elf == nullptr) {
    return;
  }
  map->load_bias = elf->GetLoadBias();
}

//-------------------------------------------------------------------------
// BacktraceMap create function.
//-------------------------------------------------------------------------
BacktraceMap* BacktraceMap::CreateNew(pid_t pid, bool uncached) {
  BacktraceMap* map;

  if (uncached) {
    // Force use of the base class to parse the maps when this call is made.
    map = new BacktraceMap(pid);
  } else if (pid == getpid()) {
    map = new UnwindStackMap(0);
  } else {
    map = new UnwindStackMap(pid);
  }
  if (!map->Build()) {
    delete map;
    return nullptr;
  }
  return map;
}
