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
    regs = new RegsX86();
    reg_size = X86_REG_LAST * sizeof(uint32_t);
    break;
  case EM_ARM:
    regs = new RegsArm();
    reg_size = ARM_REG_LAST * sizeof(uint32_t);
    break;
  case EM_X86_64:
    regs = new RegsX86_64();
    reg_size = X86_64_REG_LAST * sizeof(uint64_t);
    break;
  case EM_AARCH64:
    regs = new RegsArm64();
    reg_size = ARM64_REG_LAST * sizeof(uint64_t);
    break;
  default:
    printf("Unknown type: %d\n", type);
    exit(1);
  }

  // Read the initial register data.
  bytes = TEMP_FAILURE_RETRY(read(fd, regs->RawData(), reg_size));
  if (bytes == -1 || static_cast<size_t>(bytes) != reg_size) {
    printf("Failed to read initial register values: %s\n", strerror(errno));
    exit(1);
  }

  MapInfo* map_info = maps.Find(regs->pc());
  Elf* elf = GetElf(map_info);
  printf("%s\n", map_info->name.c_str());
  printf("pc     = 0x%" PRIx64 "\n", regs->pc());
  uint64_t rel_pc = regs->GetRelPc(elf, map_info);
  printf("rel_pc = 0x%" PRIx64 "\n", rel_pc);
  printf("sp     = 0x%" PRIx64 "\n\n", regs->sp());
  while (elf != nullptr) {
    if (!elf->Step(rel_pc, regs, &memory)) {
      break;
    }

#if 0
    uint64_t pc = regs->pc();
    map_info = maps.Find(pc);
    elf = GetElf(map_info);
    rel_pc = regs->GetRelPc(pc, elf, map_info);
    uint64_t adjusted_rel_pc = rel_pc;
    if (frame_num != 0) {
      adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
    }
    printf("%s\n", map_info->name.c_str());
    printf("pc     = 0x%" PRIx64 "\n", pc);
    printf("rel_pc = 0x%" PRIx64 "\n", adjusted_rel_pc);
    printf("sp     = 0x%" PRIx64 "\n\n", regs->sp());
#endif
  }

  return 0;
}
