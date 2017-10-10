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

#define _GNU_SOURCE 1
#include <link.h>
#include <stdint.h>
#include <sys/mman.h>

#include <algorithm>
#include <memory>

#include <unwindstack/Memory.h>

#include "DlPhdrMaps.h"
#include "ElfLocal.h"

namespace unwindstack {

struct CallbackData {
  DlPhdrMaps* maps;
  std::shared_ptr<Memory>* process_memory;
};

int DlPhdrMaps::Callback(struct dl_phdr_info* info, size_t size, void* data) {
  if (size < sizeof(struct dl_phdr_info)) {
    return 0;
  }

  uint64_t phdr_offset = reinterpret_cast<uint64_t>(info->dlpi_phdr);
  if (phdr_offset < info->dlpi_addr) {
    return 0;
  }

  CallbackData* callback_data = reinterpret_cast<CallbackData*>(data);
  DlPhdrMaps* maps = callback_data->maps;
  std::shared_ptr<Memory>* process_memory = callback_data->process_memory;

  // Create a special memory object.
  MapInfo map_info;
  if (info->dlpi_name != nullptr) {
    map_info.name = info->dlpi_name;
  }
  map_info.offset = 0;
  map_info.elf_offset = 0;
  // Set reasonable defaults.
  map_info.flags = PROT_READ | PROT_EXEC;

  // Create a special Elf object for this.
  std::unique_ptr<ElfLocal> elf(
      new ElfLocal(new MemoryRange(*process_memory, info->dlpi_addr, UINT64_MAX)));
  if (!elf->Init(phdr_offset - map_info.start, info->dlpi_phnum)) {
    // Keep going, but ignore this particular entry.
    return 0;
  }

  // Set the end address.
  uint64_t pc_max = 0;
  for (auto& entry : elf->interface()->pt_loads()) {
    uint64_t load_max = entry.second.table_offset + entry.second.table_size;
    if (load_max > pc_max) {
      pc_max = load_max;
    }
  }

  map_info.start = info->dlpi_addr + elf->GetLoadBias();
  map_info.end = info->dlpi_addr + pc_max;
  map_info.elf = elf.release();

  maps->maps_.push_back(map_info);
  return 0;
}

void DlPhdrMaps::Init(std::shared_ptr<Memory>& process_memory) {
  CallbackData callback_data{.maps = this, .process_memory = &process_memory};
  dl_iterate_phdr(DlPhdrMaps::Callback, &callback_data);
  std::sort(maps_.begin(), maps_.end(), [](auto& a, auto& b) { return a.start < b.start; });
}

}  // namespace unwindstack
