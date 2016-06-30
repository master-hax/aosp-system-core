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

#define LOG_TAG "unwind"
#include <log/log.h>

#include "Elf.h"
#include "ElfInterface.h"
#include "Memory.h"

#if !defined(__BIONIC__) && !defined(EM_AARCH64)
#define EM_AARCH64 183
#endif

bool Elf::Init() {
  uint8_t e_ident[EI_CLASS + 1];

  // Verify that this is a valid elf file.
  if (!memory_->Read(0, e_ident, EI_CLASS + 1)) {
    return false;
  }

  if (memcpy(e_ident, ELFMAG, SELFMAG) != 0) {
    return false;
  }

  if (e_ident[EI_CLASS] == ELFCLASS32) {
    // Read the machine type.
    Elf32_Ehdr ehdr;
    if (!GET_FIELD(0, Elf32_Ehdr, e_machine, ehdr.e_machine)) {
      return false;
    }

    if (ehdr.e_machine != EM_ARM && ehdr.e_machine != EM_386) {
      // Unsupported.
      ALOGI("32 bit elf that is neither arm nor x86: e_machine = %d\n", ehdr.e_machine);
      return false;
    }

    interface_.reset(new ElfInterface32(memory_));

    valid_ = interface_->ProcessProgramHeaders();
  } else if (e_ident[EI_CLASS] == ELFCLASS64) {
    Elf64_Ehdr ehdr;
    if (!GET_FIELD(0, Elf64_Ehdr, e_machine, ehdr.e_machine)) {
      return false;
    }

    if (ehdr.e_machine != EM_AARCH64 && ehdr.e_machine != EM_X86_64) {
      // Unsupported.
      ALOGI("64 bit elf that is neither aarch64 nor x86_64: e_machine = %d\n", ehdr.e_machine);
      return false;
    }

    interface_.reset(new ElfTemplateInterface<Elf64_Ehdr, Elf64_Phdr, LoadInfo64>(memory_));

    valid_ = interface_->ProcessProgramHeaders();
  }
  return valid_;
}

bool Elf::Unwind() {
  if (!valid_) {
    return false;
  }
  return interface_->Unwind();
}
