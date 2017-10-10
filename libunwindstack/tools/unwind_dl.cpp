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
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <unwindstack/Elf.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>
#include <unwindstack/Unwinder.h>
#include "DlPhdrMaps.h"

#if defined(__LP64__)
#define WIDTH "016"
#else
#define WIDTH "08"
#endif

void Level5() {
  unwindstack::DlPhdrMaps maps;
  auto process_memory(unwindstack::Memory::CreateProcessMemory(getpid()));
  maps.Init(process_memory);

  std::unique_ptr<unwindstack::Regs> regs(unwindstack::Regs::CreateFromLocal());
  RegsGetLocal(regs.get());

  printf("ABI: ");
  switch (regs->MachineType()) {
    case EM_ARM:
      printf("arm");
      break;
    case EM_386:
      printf("x86");
      break;
    case EM_AARCH64:
      printf("arm64");
      break;
    case EM_X86_64:
      printf("x86_64");
      break;
    default:
      printf("unknown\n");
      return;
  }
  printf("\n");

  size_t frame = 0;
  while (true) {
    unwindstack::MapInfo* map_info = maps.Find(regs->pc());
    if (map_info == nullptr) {
      printf("  #%02zx %" WIDTH PRIx64 " <unknown>\n", frame, regs->pc());
      break;
    }

    unwindstack::Elf* elf = map_info->elf;
    if (elf == nullptr) {
      // This should never happen.
      printf("  #%02zx %" WIDTH PRIx64 " <unknown>\n", frame, regs->pc());
      break;
    }

    uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);
    printf("  #%02zx %" WIDTH PRIx64, frame, rel_pc);
    if (!map_info->name.empty()) {
      printf(" %s", map_info->name.c_str());
    } else {
      printf(" <anonymous:%" PRIx64 ">", map_info->start);
    }

    std::string function_name;
    uint64_t function_offset;
    if (elf->GetFunctionName(regs->pc(), &function_name, &function_offset)) {
      printf(" (%s", function_name.c_str());
      if (function_offset != 0) {
        printf("+%" PRId64, function_offset);
      }
      printf(")");
    }
    printf("\n");

    bool finished;
    if (!elf->Step(rel_pc + map_info->elf_offset, regs.get(), process_memory.get(), &finished) ||
        finished) {
      break;
    }
    frame++;
  }

  for (auto& map : maps) {
    printf("Map: %" PRIx64 " %" PRIx64, map.start, map.end);
    if (!map.name.empty()) {
      printf(" %s", map.name.c_str());
    }
    printf("\n");
  }
}

void Level4() {
  Level5();
}

void Level3() {
  Level4();
}

void Level2() {
  Level3();
}

void Level1() {
  Level2();
}

int main() {
  Level1();

  printf("pid: %d\n", getpid());
  sleep(200);
  return 0;
}
