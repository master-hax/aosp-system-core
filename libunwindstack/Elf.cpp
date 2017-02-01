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
#include <string.h>

#include <memory>
#include <string>

#define LOG_TAG "unwind"
#include <log/log.h>

#include "Elf.h"
#include "ElfInterface.h"
#include "ElfInterfaceArm.h"
#include "Machine.h"
#include "Memory.h"

bool Elf::Init() {
  if (memory_.get() == nullptr) {
    return false;
  }

  uint8_t e_ident[EI_CLASS + 1];

  // Verify that this is a valid elf file.
  if (!memory_->Read(0, e_ident, EI_CLASS + 1)) {
    return false;
  }

  if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
    return false;
  }

  class_type_ = e_ident[EI_CLASS];
  if (e_ident[EI_CLASS] == ELFCLASS32) {
    Elf32_Half e_machine;
    if (!memory_->Read(EI_NIDENT + sizeof(Elf32_Half), &e_machine, sizeof(e_machine))) {
      return false;
    }

    if (e_machine != EM_ARM && e_machine != EM_386) {
      // Unsupported.
      ALOGI("32 bit elf that is neither arm nor x86: e_machine = %d\n", e_machine);
      return false;
    }

    machine_type_ = e_machine;
    class_type_ = e_ident[EI_CLASS];
    if (e_machine == EM_ARM) {
      interface_.reset(new ElfInterfaceArm(memory_.get()));
    } else {
      interface_.reset(new ElfInterface32(memory_.get()));
    }
  } else if (e_ident[EI_CLASS] == ELFCLASS64) {
    Elf64_Half e_machine;
    if (!memory_->Read(EI_NIDENT + sizeof(Elf64_Half), &e_machine, sizeof(e_machine))) {
      return false;
    }

    if (e_machine != EM_AARCH64 && e_machine != EM_X86_64) {
      // Unsupported.
      ALOGI("64 bit elf that is neither aarch64 nor x86_64: e_machine = %d\n", e_machine);
      return false;
    }

    machine_type_ = e_machine;
    interface_.reset(new ElfInterface64(memory_.get()));
  }

  valid_ = interface_->Init();
  if (!valid_) {
    interface_.reset(nullptr);
  }
  return valid_;
}

bool Elf::Step(uint64_t pc, Regs* regs, Memory* process_memory) {
  return valid_ && interface_->Step(pc, regs, process_memory);
}

bool Elf::GetSoname(std::string* name) {
  return valid_ && interface_->GetSoname(name);
}

bool Elf::GetFunctionName(uint64_t addr, std::string* name, uint64_t* func_offset) {
  return valid_ && interface_->GetFunctionName(addr, name, func_offset);
}
