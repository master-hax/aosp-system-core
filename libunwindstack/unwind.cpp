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

#include "Elf.h"
#include "Maps.h"
#include "Memory.h"
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

void print_regs(Regs* regs) {
  printf("\n");
  printf("SP = %" PRIx64 "\n", regs->sp());
  printf("PC = %" PRIx64 "\n", regs->pc());
}

extern "C" void call_level4() {
  while (true);
}

extern "C" void call_level3() {
  call_level4();
}

extern "C" void call_level2() {
  call_level3();
}

extern "C" void call_level1() {
  call_level2();
}

void do_unwind(pid_t pid) {
  printf("Attaching to %d\n", pid);

  if (!Attach(pid)) {
    printf("Failed to attach to pid %d: %s\n", pid, strerror(errno));
    return;
  }

  MapsRemote remote_maps(pid);
  if (!remote_maps.Parse()) {
    printf("Failed to parse map data.\n");
    return;
  }

  Regs* regs = RemoteGetRegs(pid);
  if (regs == nullptr) {
    printf("Unable to get remote reg data\n");
    return;
  }

  MemoryRemote remote_memory(pid);

  for (size_t i = 0; i < 64; i++) {
    print_regs(regs);
    if (regs->pc() == 0) {
      break;
    }
    MapInfo* map_info = remote_maps.Find(regs->pc());
    if (map_info == nullptr) {
      printf("Failed to find map data for the pc\n");
      printf("  0x%" PRIx64 "\n", regs->pc());
      break;
    }

    Elf* elf = map_info->elf;
    if (elf == nullptr) {
      elf = new Elf(map_info->CreateMemory(getpid()));
      if (!elf->Init()) {
        printf("Failed to init elf object.\n");
        break;
      }
      map_info->elf = elf;
    }
    uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);
    std::string name;
    if (elf->GetFunctionName(rel_pc, &name)) {
      printf("  Function: <0x%" PRIx64 "> %s\n", rel_pc, name.c_str());
    } else {
      printf("  Function: <0x%" PRIx64 "> unknown\n", rel_pc);
    }

    if (!elf->Step(rel_pc, regs, &remote_memory)) {
      break;
    }
  }
}

int main(int argc, char** argv) {
  pid_t pid;
  bool forked = false;

  if (argc == 2) {
    pid = atoi(argv[1]);
  } else {
    if ((pid = fork()) == 0) {
      call_level1();
      exit(1);
    }
    sleep(1);
    forked = true;
  }

  do_unwind(pid);

  if (forked) {
    Detach(pid);
    kill(pid, SIGKILL);
  }

  return 0;
}
