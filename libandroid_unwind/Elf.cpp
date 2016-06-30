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
#include "Maps.h"
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

  void (*dwarf_init_loc_func)(dwarf_loc_regs_t*) = nullptr;
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
      dwarf_init_loc_func = Arm::InitLocationRegs;
    } else {
      interface_.reset(new ElfInterface32(memory_.get()));
      dwarf_init_loc_func = X86::InitLocationRegs;
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
    if (e_machine == EM_AARCH64) {
      dwarf_init_loc_func = Arm64::InitLocationRegs;
    } else {
      dwarf_init_loc_func = X86_64::InitLocationRegs;
    }
  }

  valid_ = interface_->ProcessProgramHeaders();
  if (valid_) {
    interface_->set_dwarf_init_loc_func(dwarf_init_loc_func);
    interface_->InitEhFrame();
  } else {
    interface_.reset(nullptr);
  }
  return valid_;
}

const std::string& Elf::GetSoname() {
  if (soname_.empty() && valid_ && interface_.get() != nullptr) {
    soname_ = interface_->ReadSoname();
  }
  return soname_;
}

uint64_t Elf::GetRelPc(uint64_t pc, MapInfo* map_info) {
  if (!valid_) {
    return 0;
  }
  return interface_->GetRelPc(pc, map_info);
}
