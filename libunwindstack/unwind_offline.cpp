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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <unordered_map>
#include <vector>

#include "DwarfStructs.h"
#include "Elf.h"
#include "Machine.h"
#include "Maps.h"
#include "Memory.h"
#include "Local.h"
#include "Remote.h"
#include "Regs.h"

Elf* GetElf(MapInfo* map_info) {
  if (map_info == nullptr) {
    return nullptr;
  }

  if (map_info->elf) {
    return map_info->elf;
  }

  MemoryFileAtOffset* elf_memory = new MemoryFileAtOffset;
  if (!elf_memory->Init(map_info->name, map_info->offset)) {
    return nullptr;
  }

  Elf* elf = new Elf(elf_memory);
  map_info->elf = elf;
  if (!elf->Init()) {
    return nullptr;
  }
  return elf;
}

int main() {
  MapsOffline maps("offline_maps.bin");

  if (!maps.Parse()) {
    printf("Failed to Parse.\n");
    return 0;
  }

  MemoryOffline memory;

  if (!memory.Init("offline_memory.bin", 0)) {
    printf("Failed to Init.\n");
    return 0;
  }
  // Read the type and the register values.
  int fd = TEMP_FAILURE_RETRY(open("offline_regs.bin", O_RDONLY));
  if (fd == -1) {
    printf("Cannot open offline_regs.bin\n");
    exit(1);
  }
  uint16_t type;
  ssize_t bytes = TEMP_FAILURE_RETRY(read(fd, &type, sizeof(type)));
  if (bytes == -1 || bytes != sizeof(type)) {
    printf("Failed to read values: %s\n", strerror(errno));
    exit(1);
  }

  Regs* regs = nullptr;
  std::vector<uint64_t> buffer(4096);
  size_t reg_size = 0;
  switch (type) {
  case EM_386:
    regs = X86::CreateRegs(buffer);
    break;
  case EM_ARM:
    regs = Arm::CreateRegs(buffer);
    break;
  case EM_X86_64:
    regs = X86_64::CreateRegs(buffer);
    break;
  case EM_AARCH64:
    regs = Arm64::CreateRegs(buffer);
    break;
  default:
    printf("Unknown type: %d\n", type);
    exit(1);
  }

  // Read the initial register data.
  bytes = TEMP_FAILURE_RETRY(read(fd, buffer.data(), reg_size));
  if (bytes == -1 || static_cast<size_t>(bytes) != reg_size) {
    printf("Failed to read initial register values: %s\n", strerror(errno));
    exit(1);
  }

  MapInfo* map_info = maps.Find(regs->pc());
  Elf* elf = GetElf(map_info);
  printf("%s\n", map_info->name.c_str());
  printf("pc     = 0x%" PRIx64 "\n", regs->pc());
  printf("rel_pc = 0x%" PRIx64 "\n", elf->GetRelPc(regs->pc(), map_info));
  printf("sp     = 0x%" PRIx64 "\n\n", regs->sp());
  uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);
  while (elf != nullptr) {
    if (!elf->Step(rel_pc, regs, &memory)) {
      break;
    }

    uint64_t pc = regs->pc();
    map_info = maps.Find(pc);
    elf = GetElf(map_info);
    if (elf) {
      elf->AdjustPc(regs, map_info);
      pc = regs->pc();
    }
    rel_pc = elf->GetRelPc(pc, map_info);
    printf("%s\n", map_info->name.c_str());
    printf("pc     = 0x%" PRIx64 "\n", pc);
    printf("rel_pc = 0x%" PRIx64 "\n", rel_pc);
    printf("sp     = 0x%" PRIx64 "\n\n", regs->sp());
  }

  uint64_t total_num_read_calls = memory.num_read_calls();
  uint64_t total_bytes_read = memory.bytes_read();
  printf("Calls from stack memory: %" PRId64 "\n", total_num_read_calls);
  printf("Bytes read from stack memory: %" PRId64 "\n", total_bytes_read);
  for (const auto& map_info : maps) {
    if (map_info.elf != nullptr) {
      printf("Reads from %s calls %" PRId64 "\n", map_info.name.c_str(), map_info.elf->memory()->num_read_calls());
      printf("Reads from %s calls %" PRId64 "\n", map_info.name.c_str(), map_info.elf->memory()->bytes_read());
      total_num_read_calls += map_info.elf->memory()->num_read_calls();
      total_bytes_read += map_info.elf->memory()->bytes_read();
    }
  }

  printf("Total read calls %" PRId64 "\n", total_num_read_calls);
  printf("Total bytes read %" PRId64 "\n", total_bytes_read);

  return 0;
}
