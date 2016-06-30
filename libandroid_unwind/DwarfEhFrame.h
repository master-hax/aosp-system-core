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

#ifndef _LIBANDROID_UNWIND_DWARF_EH_FRAME_H
#define _LIBANDROID_UNWIND_DWARF_EH_FRAME_H

#include <stdint.h>

#include <unordered_map>

#include "Dwarf.h"
#include "DwarfMemory.h"
#include "DwarfStructs.h"
#include "Memory.h"

template <typename AddressType>
class DwarfEhFrame : public Dwarf<AddressType> {
 public:
  DwarfEhFrame(Memory* dwarf_memory, Memory* regular_memory) : Dwarf<AddressType>(dwarf_memory, regular_memory), memory_(dwarf_memory) {}
  virtual ~DwarfEhFrame() = default;

  class iterator : public std::iterator<std::bidirectional_iterator_tag, FdeInfo> {
   public:
    iterator(DwarfEhFrame* eh_frame, size_t index) : eh_frame_(eh_frame), index_(index) {}

    iterator& operator++() { index_++; return *this; }
    iterator& operator++(int increment) { index_ += increment; return *this; }
    iterator& operator--() { index_--; return *this; }
    iterator& operator--(int decrement) { index_ -= decrement; return *this; }

    bool operator==(const iterator& rhs) { return this->index_ == rhs.index_; }
    bool operator!=(const iterator& rhs) { return this->index_ != rhs.index_; }

    FdeInfo operator*() {
      FdeInfo info = eh_frame_->fdes_[index_];
      if (info.pc == 0) {
        if (!eh_frame_->ReadEntry(index_, &info)) {
          return info;
        }
      }
      return info;
    }

   private:
    DwarfEhFrame<AddressType>* eh_frame_ = nullptr;
    size_t index_ = 0;
  };

  iterator begin() { return iterator(this, 0); }
  iterator end() { return iterator(this, fde_count_); }

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

    return true;
  }

  bool ReadEntry(size_t entry, FdeInfo* info) {
    memory_.set_cur_offset(entries_offset_ + 2 * entry * table_size_);
    memory_.set_pc_offset(memory_.cur_offset());
    if (!memory_.ReadEncodedValue(table_encoding_, &info->pc)) {
      return false;
    }
    if (!memory_.ReadEncodedValue(table_encoding_, &info->offset)) {
      return false;
    }
    fdes_[entry] = *info;
    return true;
  }

  bool GetFdeOffset(uint64_t pc, uint64_t* fde_offset) {
    if (fde_count_ == 0) {
      return false;
    }

    memory_.set_data_offset(ptr_offset_);

    if (table_size_ > 0) {
      // The size of the entries is a constant so do a binary search.
      size_t first = 0;
      size_t last = fde_count_;
      while (first <= last) {
        size_t current = first + (last - first) / 2;
        FdeInfo info = fdes_[current];
        if (info.offset == 0 && !ReadEntry(current, &info)) {
          return false;
        }
        if (pc == info.offset) {
          *fde_offset = info.pc;
          return true;
        }
        if (pc < info.offset) {
          info = fdes_[current - 1];
          if (info.offset == 0 && !ReadEntry(current, &info)) {
            return false;
          }
          if (pc >= info.offset) {
            *fde_offset = info.pc;
            return true;
          }
          last = current - 1;
        } else {
          info = fdes_[current + 1];
          if (info.offset == 0 && !ReadEntry(current, &info)) {
            return false;
          }
          if (pc < info.offset) {
            *fde_offset = info.offset;
            return true;
          }
          first = current + 1;
        }
      }
    } else {
      // The size of the entries is not constant, do a sequential search.
      FdeInfo info = fdes_[0];
      if (info.offset == 0 && !ReadEntry(0, &info)) {
        return false;
      }
      if (pc < info.pc) {
        return false;
      }
      for (size_t i = 0; i < fde_count_; i++) {
        if (info.offset == 0 && !ReadEntry(i, &info)) {
          return false;
        }
        if (pc < info.pc) {
          break;
        }
      }
      *fde_offset = info.offset;
      return true;
    }
    return false;
  }

 private:
  uint8_t version_;
  uint8_t ptr_encoding_;
  uint8_t table_encoding_;
  size_t table_size_;
  uint64_t fde_count_;
  uint64_t frame_offset_;

  uint64_t ptr_offset_;

  uint64_t entries_offset_;

  DwarfMemory<AddressType> memory_;
  std::unordered_map<size_t, FdeInfo> fdes_;
};

#endif  // _LIBANDROID_UNWIND_DWARF_EH_FRAME_H
