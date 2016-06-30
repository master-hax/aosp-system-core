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

#ifndef _LIBANDROID_UNWIND_ELF_INTERFACE_ARM_H
#define _LIBANDROID_UNWIND_ELF_INTERFACE_ARM_H

#include <stdint.h>
#include <elf.h>

#include <iterator>
#include <unordered_map>

#include "Arm.h"
#include "Memory.h"

class ElfInterfaceArm {
 public:
  ElfInterfaceArm(Memory* memory, uint64_t start_offset, size_t size);
  virtual ~ElfInterfaceArm() = default;

  bool FindEntry(arm_ptr_t ip, uint64_t* entry_offset);

  class iterator : public std::iterator<std::bidirectional_iterator_tag, arm_ptr_t> {
   public:
    iterator(ElfInterfaceArm* interface, size_t index) : interface_(interface), index_(index) { }

    iterator& operator++() { index_++; return *this; }
    iterator& operator++(int increment) { index_ += increment; return *this; }
    iterator& operator--() { index_--; return *this; }
    iterator& operator--(int decrement) { index_ -= decrement; return *this; }

    bool operator==(const iterator& rhs) { return this->index_ == rhs.index_; }
    bool operator!=(const iterator& rhs) { return this->index_ != rhs.index_; }

    arm_ptr_t operator*() {
      arm_ptr_t addr = interface_->addrs_[index_];
      if (addr == 0) {
        if (!interface_->GetPrel31Addr(interface_->start_offset_ + index_ * 8, &addr)) {
          return 0;
        }
        interface_->addrs_[index_] = addr;
      }
      return addr;
    }

   private:
    ElfInterfaceArm* interface_ = nullptr;
    size_t index_ = 0;
  };

  iterator begin() { return iterator(this, 0); }
  iterator end() { return iterator(this, total_entries_); }

 private:
  bool GetPrel31Addr(arm_ptr_t offset, arm_ptr_t* addr);

  Memory* memory_ = nullptr;
  uint64_t start_offset_ = 0;
  size_t total_entries_ = 0;

  std::unordered_map<size_t, uint64_t> addrs_;
  arm_ptr_t first_addr_ = 0;
  arm_ptr_t last_addr_ = 0;
};

#endif  // _LIBANDROID_UNWIND_ELF_INTERFACE_ARM_H
