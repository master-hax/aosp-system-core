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

#include <assert.h>
#include <stdint.h>

#include "DwarfEhFrame.h"
#include "DwarfMemory.h"
#include "DwarfSection.h"
#include "DwarfStructs.h"
#include "Memory.h"

template <typename AddressType>
bool DwarfEhFrame<AddressType>::Init(uint64_t offset, uint64_t) {
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
  table_size_ = memory_.template GetEncodedSize<AddressType>(table_encoding_);

  memory_.set_pc_offset(memory_.cur_offset());
  if (!memory_.template ReadEncodedValue<AddressType>(ptr_encoding_, &ptr_offset_)) {
    return false;
  }

  memory_.set_pc_offset(memory_.cur_offset());
  if (!memory_.template ReadEncodedValue<AddressType>(fde_count_encoding, &fde_count_)) {
    return false;
  }

  entries_offset_ = memory_.cur_offset();
  entries_data_offset_ = offset;

  return true;
}

template <typename AddressType>
const DwarfFDE* DwarfEhFrame<AddressType>::GetFDEFromIndex(size_t index) {
  const FDEInfo* info = GetFDEInfoFromIndex(index);
  if (info == nullptr) {
    return nullptr;
  }
  return this->GetFDEFromOffset(info->offset);
}

template <typename AddressType>
const typename DwarfEhFrame<AddressType>::FDEInfo* DwarfEhFrame<AddressType>::GetFDEInfoFromIndex(
    size_t index) {
  auto entry = fde_info_.find(index);
  if (entry != fde_info_.end()) {
    return &fde_info_[index];
  }
  FDEInfo* info = &fde_info_[index];

  memory_.set_data_offset(entries_data_offset_);
  memory_.set_cur_offset(entries_offset_ + 2 * index * table_size_);
  memory_.set_pc_offset(memory_.cur_offset());
  uint64_t value;
  if (!memory_.template ReadEncodedValue<AddressType>(table_encoding_, &value)) {
    return nullptr;
  }
  info->pc = value;

  if (!memory_.template ReadEncodedValue<AddressType>(table_encoding_, &info->offset)) {
    return nullptr;
  }
  return info;
}

template <typename AddressType>
bool DwarfEhFrame<AddressType>::GetFDEOffsetBinary(
    uint64_t pc, uint64_t* fde_offset, uint64_t total_entries) {
  assert(fde_count_ > 0);

  size_t first = 0;
  size_t last = total_entries;
  while (first < last) {
    size_t current = (first + last) / 2;
    const FDEInfo* info = GetFDEInfoFromIndex(current);
    if (pc == info->pc) {
      *fde_offset = info->offset;
      return true;
    }
    if (pc < info->pc) {
      last = current;
    } else {
      first = current + 1;
    }
  }
  if (last != 0) {
    const FDEInfo* info = GetFDEInfoFromIndex(last - 1);
    *fde_offset = info->offset;
    return true;
  }
  return false;
}

template <typename AddressType>
bool DwarfEhFrame<AddressType>::GetFDEOffsetSequential(uint64_t pc, uint64_t* fde_offset) {
  // We can do a binary search if the pc is less than the last entry
  // we read before.
  if (!fde_info_.empty()) {
    const FDEInfo* info = &fde_info_[fde_info_.size() - 1];
    if (pc == info->pc) {
      *fde_offset = info->offset;
      return true;
    }
    if (pc < info->pc) {
      return GetFDEOffsetBinary(pc, fde_offset, fde_info_.size());
    }
  }

  if (last_entries_offset_ == 0) {
    last_entries_offset_ = entries_offset_;
  }
  memory_.set_data_offset(entries_data_offset_);
  memory_.set_cur_offset(last_entries_offset_);

  for (size_t current = fde_info_.size(); true; current++) {
    FDEInfo* info = &fde_info_[current];
    memory_.set_pc_offset(memory_.cur_offset());
    uint64_t value;
    if (!memory_.template ReadEncodedValue<AddressType>(table_encoding_, &value)) {
      last_entries_offset_ = 0;
      return false;
    }
    info->pc = value;

    if (!memory_.template ReadEncodedValue<AddressType>(table_encoding_, &info->offset)) {
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

template <typename AddressType>
bool DwarfEhFrame<AddressType>::GetFDEOffsetFromPc(uint64_t pc, uint64_t* fde_offset) {
  if (fde_count_ == 0) {
    return false;
  }

  if (table_size_ > 0) {
    // Do a binary search since the size of each table entry is fixed.
    return GetFDEOffsetBinary(pc, fde_offset, fde_count_);
  } else {
    // Do a sequential search since each table entry size is variable.
    return GetFDEOffsetSequential(pc, fde_offset);
  }
}

// Explicitly instantiate DwarfEhFrame.
template class DwarfEhFrame<uint32_t>;
template class DwarfEhFrame<uint64_t>;
