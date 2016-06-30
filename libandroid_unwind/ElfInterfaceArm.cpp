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

#include <stdint.h>

#include <unordered_map>

#include "ArmExidx.h"
#include "ElfInterfaceArm.h"
#include "Memory.h"

// Ip must have already been adjusted for any load bias.
bool ElfInterfaceArm::FindEntry(uint32_t pc, uint64_t* entry_offset) {
  if (start_offset_ == 0 || total_entries_ == 0) {
    return false;
  }

  if (first_addr_ == 0) {
    // This is the first time we've read this.
    uint32_t addr;
    if (!GetPrel31Addr(start_offset_, &addr)) {
      return false;
    }
    addrs_[0] = addr;
    first_addr_ = addr;
    if (total_entries_ > 1) {
      size_t entry = total_entries_ - 1;
      if (!GetPrel31Addr(start_offset_ + entry * 8, &addr)) {
        return false;
      }
      addrs_[entry] = addr;
    }
    last_addr_ = addr;
  }

  if (pc < first_addr_) {
    return false;
  }

  if (pc >= last_addr_) {
    *entry_offset = start_offset_ + (total_entries_ - 1) * 8;
    return true;
  }

  size_t first = 0;
  size_t last = total_entries_ - 2;
  while (first <= last) {
    size_t current = first + (last - first) / 2;
    uint32_t addr = addrs_[current];
    if (addr == 0) {
      if (!GetPrel31Addr(start_offset_ + current * 8, &addr)) {
        return false;
      }
      addrs_[current] = addr;
    }
    if (pc == addr) {
      *entry_offset = start_offset_ + current * 8;
      return true;
    }
    if (pc < addr) {
      addr = addrs_[current - 1];
      if (addr == 0) {
        if (!GetPrel31Addr(start_offset_ + (current - 1) * 8, &addr)) {
          return false;
        }
        addrs_[current - 1] = addr;
      }
      if (pc >= addr) {
        *entry_offset = start_offset_ + (current - 1) * 8;
        return true;
      }
      last = current - 1;
    } else {
      addr = addrs_[current + 1];
      if (addr == 0) {
        if (!GetPrel31Addr(start_offset_ + (current + 1) * 8, &addr)) {
          return false;
        }
        addrs_[current + 1] = addr;
      }
      if (pc < addr) {
        *entry_offset = start_offset_ + current * 8;
        return true;
      }
      first = current + 1;
    }
  }
  return false;
}

bool ElfInterfaceArm::GetPrel31Addr(uint32_t offset, uint32_t* addr) {
  uint32_t data;
  if (!memory_->Read32(offset, &data)) {
    return false;
  }

  // Sign extend the value if necessary.
  int32_t value = (static_cast<int32_t>(data) << 1) >> 1;
  *addr = offset + value;
  return true;
}

#if !defined(PT_ARM_EXIDX)
#define PT_ARM_EXIDX 0x70000001
#endif

bool ElfInterfaceArm::HandleType(uint64_t offset, const Elf32_Phdr& phdr) {
  if (phdr.p_type == PT_ARM_EXIDX) {
    Elf32_Phdr phdr;
    if (!memory_->Read(offset, &phdr, &phdr.p_vaddr, sizeof(phdr.p_vaddr))) {
      return true;
    }
    if (!memory_->Read(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
      return true;
    }
    start_offset_ = phdr.p_vaddr;
    total_entries_ = phdr.p_memsz / 8;
    return true;
  }
  return false;
}

bool ElfInterfaceArm::Step(Regs* regs, Memory* process_memory) {
  Regs32* regs32 = reinterpret_cast<Regs32*>(regs);
  if (StepExidx(regs32, process_memory)) {
    return true;
  }
  return ElfInterface32::Step(regs, process_memory);
}

bool ElfInterfaceArm::StepExidx(Regs32* regs, Memory* process_memory) {
  // First try arm, then try dwarf.
  uint64_t entry_offset;
  if (!FindEntry(regs->pc(), &entry_offset)) {
    return false;
  }
  ArmExidx arm(regs, memory_, process_memory);
  if (arm.ExtractEntry(entry_offset) && arm.Eval()) {
    return true;
  }
  return false;
}
