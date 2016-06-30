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

static constexpr size_t NS_PER_SEC = 1000000000ULL;

class ElfCache {
 public:
  ElfCache() = default;
  virtual ~ElfCache() = default;

  void ClearCache();

 private:
  std::vector<Elf*> cache_;
};

static uint64_t NanoTime() {
  struct timespec t = { 0, 0 };
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec * NS_PER_SEC + t.tv_nsec);
}

static bool Attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
    return false;
  }

  uint64_t start = NanoTime();
  siginfo_t si;
  while (TEMP_FAILURE_RETRY(ptrace(PTRACE_GETSIGINFO, pid, 0, &si)) < 0 && errno == ESRCH) {
    if ((NanoTime() - start) > 10 * NS_PER_SEC) {
      printf("%d: Failed to stop after 10 seconds.\n", pid);
      return false;
    }
    usleep(30);
  }
  return true;
}

static bool Detach(pid_t pid) {
  return ptrace(PTRACE_DETACH, pid, 0, 0) == 0;
}

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

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }

  printf("Attaching to %d\n", pid);

  if (!Attach(pid)) {
    printf("Failed to attach\n");
    return 1;
  }

  {
  MapsRemote remote_maps(pid);

  Regs* regs = nullptr;
  std::vector<uint64_t> buffer(4096);
  uint32_t type = RemoteGetRegs(pid, buffer.data());
  switch (type) {
  case EM_386:
    regs = new Regs32(X86::PcReg(), X86::SpReg(), buffer.data());
    break;
  case EM_ARM:
    regs = new Regs32(Arm::PcReg(), Arm::SpReg(), buffer.data());
    break;
  case EM_X86_64:
    regs = new Regs64(X86_64::PcReg(), X86_64::SpReg(), buffer.data());
    break;
  case EM_AARCH64:
    regs = new Regs64(Arm64::PcReg(), Arm64::SpReg(), buffer.data());
    break;
  default:
    printf("Unknown type: %d\n", type);
  }

  if (regs != nullptr) {
    MemoryByPid remote_memory(pid);

    MapInfo* map_info = remote_maps.Find(regs->pc());
    if (map_info != nullptr) {
      Elf* elf = new Elf(map_info->CreateMemory(getpid()));
      map_info->elf = elf;
      if (!elf->Init()) {
        printf("Failed to init elf object.\n");
      } else {
        if (!elf->Step(elf->GetRelPc(regs->pc(), map_info), regs, &remote_memory)) {
          printf("Failed to step.\n");
        }
      }
    }
  }

  Detach(pid);

  kill(pid, SIGKILL);
  }

  return 0;
}
