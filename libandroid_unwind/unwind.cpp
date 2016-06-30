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
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <unordered_map>
#include <vector>

#include "Elf.h"
#include "Maps.h"
#include "Memory.h"
#if 0
#include "Elf.h"
#include "ElfInterface.h"
#include "ElfInterfaceArm.h"
#include "Dwarf.h"
#include "DwarfStructs.h"
#include "ArmUnwind.h"
#endif

class ElfCache {
 public:
  ElfCache() = default;
  virtual ~ElfCache() = default;

  void ClearCache();

 private:
  std::vector<Elf*> cache_;
};

int main() {
  MapsLocal maps;
  if (!maps.Parse()) {
    printf("Failed to parse maps file.\n");
    return 1;
  }

  for (auto& map : maps) {
    map.elf = new Elf(map.CreateMemory(getpid()));
    if (!map.elf->Init()) {
      delete map.elf;
      map.elf = nullptr;
    }
    if (map.elf == nullptr) {
      printf("Failure: ");
    } else {
      printf("Passed: ");
    }
    printf("0x%" PRIx64 ":%" PRIx64, map.start, map.offset);
    if (!map.name.empty()) {
      printf(" %s\n", map.name.c_str());
    } else {
      printf("\n");
    }
  }

  return 0;
}
