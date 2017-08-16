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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <backtrace/BacktraceMap.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>

#include "BacktraceLog.h"
#include "UnwindStackMap.h"

//-------------------------------------------------------------------------
UnwindStackMap::UnwindStackMap(pid_t pid) : BacktraceMap(pid) {}

void UnwindStackMap::FillInMap(unwindstack::MapInfo* info, backtrace_map_t* map) {
  map->start = info->start;
  map->end = info->end;
  map->offset = info->offset;
  map->load_bias = info->GetLoadBias(pid_);
  map->flags = info->flags;
  map->name = info->name;
}

backtrace_map_t UnwindStackMap::Get(size_t index) {
  unwindstack::MapInfo* info = stack_maps_->Get(index);
  backtrace_map_t map;
  FillInMap(info, &map);

  return map;
}

bool UnwindStackMap::Build() {
  if (pid_ == 0) {
    pid_ = getpid();
    stack_maps_.reset(new unwindstack::LocalMaps);
  } else {
    stack_maps_.reset(new unwindstack::RemoteMaps(pid_));
  }

  return stack_maps_->Parse();
}

void UnwindStackMap::FillIn(uintptr_t addr, backtrace_map_t* map) {
  unwindstack::MapInfo* info = stack_maps_->Find(addr);
  if (info == nullptr) {
    map->start = 0;
    map->end = 0;
    return;
  }

  FillInMap(info, map);
}

//-------------------------------------------------------------------------
// BacktraceMap create function.
//-------------------------------------------------------------------------
BacktraceMap* BacktraceMap::CreateNew(pid_t pid, bool uncached) {
  BacktraceMap* map;

  if (uncached) {
// Not allowed right now.
#if defined(__ANDROID__)
    __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__,
              "BacktraceMap::CreateNew() cannot be called with uncached true.");
#else
    BACK_LOGE("BacktraceMap::CreateNew() cannot be called with uncached true.");
    abort();
#endif
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
