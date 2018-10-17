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

#include <stdint.h>
#include <sys/mman.h>

#include <string>
#include <vector>

#include <unwindstack/Global.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

Global::Global(std::shared_ptr<Memory>& memory) : memory_(memory) {}
Global::Global(std::shared_ptr<Memory>& memory, std::vector<std::string>& search_libs)
    : memory_(memory), search_libs_(search_libs) {}

uint64_t Global::GetVariableOffset(MapInfo* info, const std::string& variable) {
  if (!search_libs_.empty()) {
    bool found = false;
    const char* lib = basename(info->name.c_str());
    for (const std::string& name : search_libs_) {
      if (name == lib) {
        found = true;
        break;
      }
    }
    if (!found) {
      return 0;
    }
  }

  Elf* elf = info->GetElf(memory_, true);
  uint64_t ptr;
  // Find first non-empty list (libraries might be loaded multiple times).
  if (elf->GetGlobalVariable(variable, &ptr) && ptr != 0) {
    return ptr + info->start;
  }
  return 0;
}

void Global::FindAndReadVariable(Maps* maps, const char* var_str) {
  std::string variable(var_str);
  // When looking for global variables, there should be this pattern of
  // maps:
  //   0xf0000 0 /path/to/elf  r--
  //   0xf1000 0x1000 /path/to/elf  rw-
  MapInfo* map_start = nullptr;
  for (MapInfo* info : *maps) {
    if (map_start != nullptr) {
      if (map_start->name == info->name) {
        if (info->offset != 0 &&
            (info->flags & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE)) {
          uint64_t ptr = GetVariableOffset(map_start, variable);
          if (ptr != 0 && ReadVariableData(ptr)) {
            break;
          } else {
            // Failed to find the global variable, skip this file.
            map_start = nullptr;
          }
        }
      } else {
        map_start = nullptr;
      }
    }
    if (map_start == nullptr && (info->flags & PROT_READ) && info->offset == 0 &&
        !info->name.empty()) {
      map_start = info;
    }
  }
}

}  // namespace unwindstack
