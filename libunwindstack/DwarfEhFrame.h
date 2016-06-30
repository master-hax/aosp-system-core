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

#include "DwarfSection.h"

// Forward declarations.
class Memory;

template <typename AddressType>
class DwarfEhFrame : public DwarfSectionTmpl<AddressType> {
  // Add these so that the protected members of DwarfSectionTmpl
  // can be accessed without needing a this->.
  using DwarfSectionTmpl<AddressType>::memory_;
  using DwarfSectionTmpl<AddressType>::fde_count_;

  struct FDEInfo {
    AddressType pc;
    uint64_t offset;
  };

 public:
  DwarfEhFrame(Memory* memory) : DwarfSectionTmpl<AddressType>(memory) {}
  virtual ~DwarfEhFrame() = default;

  bool Init(uint64_t offset, uint64_t size) override;

  bool GetFDEOffsetFromPc(uint64_t pc, uint64_t* fde_offset) override;

  const DwarfFDE* GetFDEFromIndex(size_t index) override;

  bool IsCIE32(uint32_t value32) override { return value32 == 0; }

  bool IsCIE64(uint64_t value64) override { return value64 == 0; }

  uint64_t GetCIEOffsetFromFDE32(uint32_t pointer) override {
    return memory_.cur_offset() - pointer - 4;
  }

  uint64_t GetCIEOffsetFromFDE64(uint64_t pointer) override {
    return memory_.cur_offset() - pointer - 8;
  }

  uint64_t AdjustPcFromFDE(uint64_t pc) override {
    // The eh_frame uses relative pcs.
    return pc + memory_.cur_offset();
  }

 protected:
  const FDEInfo* GetFDEInfoFromIndex(size_t index);

  bool GetFDEOffsetSequential(uint64_t pc, uint64_t* fde_offset);

  bool GetFDEOffsetBinary(uint64_t pc, uint64_t* fde_offset, uint64_t last_entry);

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

  std::unordered_map<uint64_t, FDEInfo> fde_info_;
};

#endif  // _LIBUNWINDSTACK_DWARF_EH_FRAME_H
