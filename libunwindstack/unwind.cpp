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
#include "Regs.h"

static constexpr size_t NS_PER_SEC = 1000000000ULL;

static uint64_t NanoTime() {
  struct timespec t = { 0, 0 };
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec * NS_PER_SEC + t.tv_nsec);
}

static bool Attach(pid_t pid) {
  printf("Attaching to %d\n", pid);

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
  printf("Detaching from %d\n", pid);
  return ptrace(PTRACE_DETACH, pid, 0, 0) == 0;
}

extern "C" void CallLevel4() {
  //sleep(100000);
  while (true);
}

extern "C" void CallLevel3() {
  CallLevel4();
}

extern "C" void CallLevel2() {
  CallLevel3();
}

extern "C" void CallLevel1() {
  CallLevel2();
}

void DoUnwind(pid_t pid) {
  MapsRemote remote_maps(pid);
  if (!remote_maps.Parse()) {
    printf("Failed to parse map data.\n");
    return;
  }

  uint32_t machine_type;
  Regs* regs = Regs::RemoteGet(pid, &machine_type);
  if (regs == nullptr) {
    printf("Unable to get remote reg data\n");
    return;
  }

  printf("ABI: ");
  switch (machine_type) {
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
    printf("unknown");
  }
  printf("\n");

  printf("New unwind method:\n");
  MemoryRemote remote_memory(pid);
  for (size_t frame_num = 0; frame_num < 64; frame_num++) {
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
      elf = new Elf(map_info->CreateMemory(pid));
      if (!elf->Init()) {
        break;
      }
      map_info->elf = elf;
    }
    if (machine_type != elf->machine_type()) {
      printf("Registers machine type does not match elf machine type.\n");
      return;
    }
    uint64_t rel_pc = regs->GetRelPc(frame_num, elf, map_info);
    std::string name;
    printf("  #%02zu pc 0x%016" PRIx64, frame_num, rel_pc);
    if (!map_info->name.empty()) {
      printf("  %s", map_info->name.c_str());
    }
    uint64_t func_offset;
    if (elf->GetFunctionName(rel_pc, &name, &func_offset)) {
      printf(" (%s", name.c_str());
      if (func_offset != 0) {
        printf("+%" PRId64, func_offset);
      }
      printf(")");
    }
    printf("\n");

    if (!elf->Step(rel_pc, regs, &remote_memory)) {
      break;
    }
  }
}

#include <backtrace/Backtrace.h>

int main(int argc, char** argv) {
  pid_t pid;
  bool forked = false;

  if (argc == 2) {
    pid = atoi(argv[1]);
    int fd = open(android::base::StringPrintf("/proc/%d/mem", pid).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
      printf("Unable to open mem of %d: %s\n", pid, strerror(errno));
    } else {
      close(fd);
    }
  } else {
    if ((pid = fork()) == 0) {
      CallLevel1();
      exit(1);
    }
    sleep(1);
    forked = true;
  }

  if (!Attach(pid)) {
    printf("Failed to attach to pid %d: %s\n", pid, strerror(errno));
    return 1;
  }

  // Use libbacktrace to get information.
  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, pid));
  if (backtrace->Unwind(0)) {
    printf("\nlibbacktrace:\n");
    for (size_t i = 0; i < backtrace->NumFrames(); i++) {
      printf("  %s\n", backtrace->FormatFrameData(i).c_str());
    }
  } else {
    printf("Failed to unwind with libbacktrace.\n");
  }

  DoUnwind(pid);

  Detach(pid);

  if (forked) {
    kill(pid, SIGKILL);
  }

  return 0;
}
