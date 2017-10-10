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

#include <dlfcn.h>
#include <elf.h>
#include <stdint.h>

#include <memory>

#include <unwindstack/Elf.h>
#include <unwindstack/ElfInterface.h>
#include <unwindstack/Memory.h>

#include "ElfInterfaceArm.h"
#include "ElfLocal.h"

#if !defined(ElfW)
#if defined(__LP64__)
#define ElfW(name) Elf64_##name
#else
#define ElfW(name) Elf32_##name
#endif
#endif

namespace unwindstack {

// This only performs a partial init. Until a call that attempts to use the elf.
bool ElfLocal::Init(uint64_t phoff, size_t phnum) {
#if defined(__arm__)
  std::unique_ptr<ElfInterfaceArm> interface(new ElfInterfaceArm(memory_.get()));
  class_type_ = ELFCLASS32;
  machine_type_ = EM_ARM;
#elif defined(__i386__)
  std::unique_ptr<ElfInterface32> interface(new ElfInterface32(memory_.get()));
  class_type_ = ELFCLASS32;
  machine_type_ = EM_386;
#elif defined(__aarch64__) || defined(__x86_64__)
  std::unique_ptr<ElfInterface64> interface(new ElfInterface64(memory_.get()));
  class_type_ = ELFCLASS64;
#if defined(__aarch64__)
  machine_type_ = EM_AARCH64;
#else
  machine_type_ = EM_X86_64;
#endif
#else
#error("Unknown architecture.");
  return false;
#endif

  ElfW(Ehdr) ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = phoff;
  ehdr.e_phnum = phnum;
  ehdr.e_phentsize = sizeof(ElfW(Phdr));
  if (!interface->ReadProgramHeaders<ElfW(Ehdr), ElfW(Phdr)>(ehdr)) {
    return false;
  }

  interface_.reset(interface.release());
  return true;
}

bool ElfLocal::GetFunctionName(uint64_t addr, std::string* name, uint64_t* func_offset) {
  Dl_info info;
  if (dladdr(reinterpret_cast<void*>(addr), &info) == 0 || info.dli_sname == nullptr ||
      info.dli_sname[0] == '\0') {
    return false;
  }
  *name = info.dli_sname;
  *func_offset = addr - reinterpret_cast<uint64_t>(info.dli_saddr);
  return true;
}

bool ElfLocal::Step(uint64_t rel_pc, Regs* regs, Memory* process_memory, bool* finished) {
  if (!full_init_) {
    interface_->InitHeaders();
    full_init_ = true;
  }
  return Elf::Step(rel_pc, regs, process_memory, finished);
}

}  // namespace unwindstack
