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

#ifndef _LIBUNWINDSTACK_DWARF_EH_FRAME_H
#define _LIBUNWINDSTACK_DWARF_EH_FRAME_H

#include <stdint.h>

#include "DwarfMemory.h"
#include "DwarfSection.h"
#include "DwarfStructs.h"
#include "Memory.h"

template <typename AddressType>
class DwarfEhFrame : public DwarfSectionTmpl<AddressType> {
  // Add these so that the protected members of DwarfSectionTmpl
  // can be accessed without needing a this->.
  using DwarfSectionTmpl<AddressType>::memory_;
  using DwarfSectionTmpl<AddressType>::fde_info_;
  using DwarfSectionTmpl<AddressType>::fde_count_;

 public:
  DwarfEhFrame(Memory* dwarf_memory, Memory* regular_memory)
      : DwarfSectionTmpl<AddressType>(dwarf_memory, regular_memory) {}
  virtual ~DwarfEhFrame() = default;

  bool Init(uint64_t offset) {
    uint8_t data[4];

    memory_.clear_func_offset();
    memory_.clear_text_offset();
    memory_.set_data_offset(offset);
    memory_.set_cur_offset(offset);

    // Read the first four bytes all at once.
    if (!memory_.ReadBytes(data, 4)) {
      return false;
    }

    version_ = data[0];
    if (version_ != 1) {
      // Unknown version.
      return false;
    }

    ptr_encoding_ = data[1];
    uint8_t fde_count_encoding = data[2];
    table_encoding_ = data[3];
    table_size_ = memory_.GetEncodedSize(table_encoding_);

    memory_.set_pc_offset(memory_.cur_offset());
    if (!memory_.ReadEncodedValue(ptr_encoding_, &ptr_offset_)) {
      return false;
    }

    memory_.set_pc_offset(memory_.cur_offset());
    if (!memory_.ReadEncodedValue(fde_count_encoding, &fde_count_)) {
      return false;
    }

    entries_offset_ = memory_.cur_offset();
    entries_data_offset_ = offset;

    return true;
  }

  const DwarfFDEInfo* GetFDEInfo(size_t index) override {
    auto entry = fde_info_.find(index);
    if (entry != fde_info_.end()) {
      return &fde_info_[index];
    }
    DwarfFDEInfo* info = &fde_info_[index];

    memory_.set_data_offset(entries_data_offset_);
    memory_.set_cur_offset(entries_offset_ + 2 * index * table_size_);
    memory_.set_pc_offset(memory_.cur_offset());
    if (!memory_.ReadEncodedValue(table_encoding_, &info->pc)) {
      return nullptr;
    }
    if (!memory_.ReadEncodedValue(table_encoding_, &info->offset)) {
      return nullptr;
    }
    return info;
  }

  bool GetFDEOffsetBinary(uint64_t pc, uint64_t* fde_offset, uint64_t last_entry) {
    const DwarfFDEInfo* info = GetFDEInfo(0);
    if (pc < info->pc) {
      return false;
    }
    info = GetFDEInfo(last_entry);
    if (pc >= info->pc) {
      *fde_offset = info->offset;
      return true;
    }

    size_t first = 1;
    size_t last = last_entry - 1;
    while (first <= last) {
      size_t current = first + (last - first) / 2;
      info = GetFDEInfo(current);
      if (pc == info->pc) {
        *fde_offset = info->offset;
        return true;
      }
      if (pc < info->pc) {
        if (current == first) {
          info = GetFDEInfo(current - 1);
          *fde_offset = info->offset;
          return true;
        }
        last = current - 1;
      } else {
        if (current == last) {
          *fde_offset = info->offset;
          return true;
        }
        first = current + 1;
      }
    }
    return false;
  }

  bool GetFDEOffsetSequential(uint64_t pc, uint64_t* fde_offset) {
    // We can do a binary search if the pc is less than the last entry
    // we read before.
    if (!fde_info_.empty()) {
      const DwarfFDEInfo* info = &fde_info_[fde_info_.size() - 1];
      if (pc == info->pc) {
        *fde_offset = info->offset;
        return true;
      }
      if (pc < info->pc) {
        return GetFDEOffsetBinary(pc, fde_offset, fde_info_.size() - 1);
      }
    }

    if (last_entries_offset_ == 0) {
      last_entries_offset_ = entries_offset_;
    }
    memory_.set_data_offset(entries_data_offset_);
    memory_.set_cur_offset(last_entries_offset_);

    for (size_t current = fde_info_.size(); true; current++) {
      DwarfFDEInfo* info = &fde_info_[current];
      memory_.set_pc_offset(memory_.cur_offset());
      if (!memory_.ReadEncodedValue(table_encoding_, &info->pc)) {
        last_entries_offset_ = 0;
        return false;
      }
      if (!memory_.ReadEncodedValue(table_encoding_, &info->offset)) {
        last_entries_offset_ = 0;
        return false;
      }
      if (pc < info->pc) {
        last_entries_offset_ = memory_.cur_offset();
        *fde_offset = info->offset;
        return true;
      }
    }
    return false;
  }

  bool GetFDEOffset(uint64_t pc, uint64_t* fde_offset) {
    if (fde_count_ == 0) {
      return false;
    }

    if (table_size_ > 0) {
      return GetFDEOffsetBinary(pc, fde_offset, fde_count_ - 1);
    } else {
      return GetFDEOffsetSequential(pc, fde_offset);
    }
  }

 private:
  uint8_t version_;
  uint8_t ptr_encoding_;
  uint8_t table_encoding_;
  size_t table_size_;
  uint64_t frame_offset_;

  uint64_t ptr_offset_;

  uint64_t entries_offset_;
  uint64_t entries_data_offset_;
  uint64_t last_entries_offset_ = 0;
};

#endif  // _LIBUNWINDSTACK_DWARF_EH_FRAME_H
