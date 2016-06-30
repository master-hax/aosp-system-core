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

#include "Elf.h"
#include "ElfInterface.h"

#if !defined(PT_ARM_EXIDX)
#define PT_ARM_EXIDX 0x70000001
#endif

bool ElfInterface32::HandleType(uint64_t offset, const Elf32_Phdr& phdr) {
  if (phdr.p_type == PT_ARM_EXIDX) {
    Elf32_Phdr phdr;
    if (!memory_->Read(offset, &phdr, &phdr.p_vaddr, sizeof(phdr.p_vaddr))) {
      return true;
    }
    if (!memory_->Read(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
      return true;
    }
    arm_.reset(new ElfInterfaceArm(memory_, phdr.p_vaddr, phdr.p_memsz));
    return true;
  }
  return false;
}
