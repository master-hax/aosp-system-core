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

#include <inttypes.h>
#include "Regs.h"
#include "Local.h"

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

#if defined(__i386__)
  uint32_t regs[256];
  memset(regs, 0, sizeof(regs));
  LocalGetRegs(reinterpret_cast<uint8_t*>(regs));
  printf("EAX = %" PRIx32 "\n", regs[X86_REG_EAX]);
  printf("ECX = %" PRIx32 "\n", regs[X86_REG_ECX]);
  printf("EDX = %" PRIx32 "\n", regs[X86_REG_EDX]);
  printf("EBX = %" PRIx32 "\n", regs[X86_REG_EBX]);
  printf("ESP = %" PRIx32 "\n", regs[X86_REG_ESP]);
  printf("EBP = %" PRIx32 "\n", regs[X86_REG_EBP]);
  printf("ESI = %" PRIx32 "\n", regs[X86_REG_ESI]);
  printf("EDI = %" PRIx32 "\n", regs[X86_REG_EDI]);
  printf("EIP = %" PRIx32 "\n", regs[X86_REG_EIP]);
  printf("CS = %" PRIx32 "\n", regs[X86_REG_CS]);
  printf("SS = %" PRIx32 "\n", regs[X86_REG_SS]);
  printf("DS = %" PRIx32 "\n", regs[X86_REG_DS]);
  printf("ES = %" PRIx32 "\n", regs[X86_REG_ES]);
  printf("FS = %" PRIx32 "\n", regs[X86_REG_FS]);
  printf("GS = %" PRIx32 "\n", regs[X86_REG_GS]);
#elif defined(__x86_64__)
  uint64_t regs[256];
  memset(regs, 0, sizeof(regs));
  LocalGetRegs(reinterpret_cast<uint8_t*>(regs));
  printf("RAX = %" PRIx64 "\n", regs[X86_64_REG_RAX]);
  printf("RBX = %" PRIx64 "\n", regs[X86_64_REG_RBX]);
  printf("RCX = %" PRIx64 "\n", regs[X86_64_REG_RCX]);
  printf("RDX = %" PRIx64 "\n", regs[X86_64_REG_RDX]);
  printf("RSI = %" PRIx64 "\n", regs[X86_64_REG_RSI]);
  printf("RDI = %" PRIx64 "\n", regs[X86_64_REG_RDI]);
  printf("RBP = %" PRIx64 "\n", regs[X86_64_REG_RBP]);
  printf("RSP = %" PRIx64 "\n", regs[X86_64_REG_RSP]);
  printf("R8 = %" PRIx64 "\n", regs[X86_64_REG_R8]);
  printf("R9 = %" PRIx64 "\n", regs[X86_64_REG_R9]);
  printf("R10 = %" PRIx64 "\n", regs[X86_64_REG_R10]);
  printf("R11 = %" PRIx64 "\n", regs[X86_64_REG_R11]);
  printf("R12 = %" PRIx64 "\n", regs[X86_64_REG_R12]);
  printf("R13 = %" PRIx64 "\n", regs[X86_64_REG_R13]);
  printf("R14 = %" PRIx64 "\n", regs[X86_64_REG_R14]);
  printf("R15 = %" PRIx64 "\n", regs[X86_64_REG_R15]);
  printf("RIP = %" PRIx64 "\n", regs[X86_64_REG_RIP]);
#endif

  return 0;
}
