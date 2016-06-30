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

#ifndef _LIBUNWINDSTACK_DWARF_GNU_DEBUGDATA_H
#define _LIBUNWINDSTACK_DWARF_GNU_DEBUGDATA_H

#include <stdint.h>

#include <vector>

#include "DwarfSection.h"

template <typename AddressType>
class DwarfGnuDebugdata : public DwarfSectionTmpl<AddressType> {
  // Add these so that the protected members of DwarfSectionTmpl
  // can be accessed without needing a this->.
  using DwarfSectionTmpl<AddressType>::memory_;
  using DwarfSectionTmpl<AddressType>::fde_count_;

 public:
  DwarfGnuDebugdata(Memory* memory) : DwarfSectionTmpl<AddressType>(memory) {}
  virtual ~DwarfGnuDebugdata() = default;

  bool Init(uint64_t offset, uint64_t size) override;

  bool GetFDEOffsetFromPc(uint64_t, uint64_t*) override { return false; }

  const DwarfFDE* GetFDEFromIndex(size_t) override { return nullptr; }

  bool IsCIE32(uint32_t value32) override { return value32 == static_cast<uint32_t>(-1); }

  bool IsCIE64(uint64_t value64) override { return value64 == static_cast<uint64_t>(-1); }

  uint64_t GetCIEOffsetFromFDE32(uint32_t pointer) override {
    return offset_ + pointer;
  }

  uint64_t GetCIEOffsetFromFDE64(uint64_t pointer) override {
    return offset_ + pointer;
  }

  uint64_t AdjustPcFromFDE(uint64_t pc) override {
    return pc;
  }

 private:
  uint64_t offset_;
  uint64_t end_offset_;

  std::vector<uint8_t> raw_;
};

#endif  // _LIBUNWINDSTACK_DWARF_GNU_DEBUGDATA_H
