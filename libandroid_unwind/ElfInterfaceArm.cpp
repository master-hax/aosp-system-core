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

#include "ElfInterfaceArm.h"
#include "Memory.h"

ElfInterfaceArm::ElfInterfaceArm(Memory* memory, uint64_t start_offset, size_t size)
    : memory_(memory), start_offset_(start_offset), total_entries_(size / 8) {
}

// Ip must have already been adjusted for any load bias.
bool ElfInterfaceArm::FindEntry(arm_ptr_t ip, uint64_t* entry_offset) {
  if (start_offset_ == 0 || total_entries_ == 0) {
    return false;
  }

  if (first_addr_ == 0) {
    // This is the first time we've read this.
    arm_ptr_t addr;
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

  if (ip < first_addr_) {
    return false;
  }

  if (ip >= last_addr_) {
    *entry_offset = start_offset_ + (total_entries_ - 1) * 8;
    return true;
  }

  size_t first = 0;
  size_t last = total_entries_ - 2;
  while (first <= last) {
    size_t current = first + (last - first) / 2;
    arm_ptr_t addr = addrs_[current];
    if (addr == 0) {
      if (!GetPrel31Addr(start_offset_ + current * 8, &addr)) {
        return false;
      }
      addrs_[current] = addr;
    }
    if (ip == addr) {
      *entry_offset = start_offset_ + current * 8;
      return true;
    }
    if (ip < addr) {
      addr = addrs_[current - 1];
      if (addr == 0) {
        if (!GetPrel31Addr(start_offset_ + (current - 1) * 8, &addr)) {
          return false;
        }
        addrs_[current - 1] = addr;
      }
      if (ip >= addr) {
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
      if (ip < addr) {
        *entry_offset = start_offset_ + current * 8;
        return true;
      }
      first = current + 1;
    }
  }
  return false;
}

bool ElfInterfaceArm::GetPrel31Addr(arm_ptr_t offset, arm_ptr_t* addr) {
  uint32_t data;
  if (!memory_->Read32(offset, &data)) {
    return false;
  }

  // Sign extend the value if necessary.
  int32_t value = (static_cast<int32_t>(data) << 1) >> 1;
  *addr = offset + value;
  return true;
}
