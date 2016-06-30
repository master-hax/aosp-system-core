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

#ifndef _LIBANDROID_UNWIND_DWARF_H
#define _LIBANDROID_UNWIND_DWARF_H

#include <stdint.h>

#include <vector>
#include <deque>
#include <unordered_map>

#include "DwarfCfa.h"
#include "DwarfError.h"
#include "DwarfMemory.h"
#include "DwarfStructs.h"
#include "Memory.h"
#include "Regs.h"

class DwarfBase {
 public:
  DwarfBase(Memory* regular_memory) : regular_memory_(regular_memory) { }
  virtual ~DwarfBase() = default;

  DwarfError last_error() { return last_error_; }

  virtual void ClearCache() { fde_entries_.clear(); cie_entries_.clear(); cie_loc_regs_.clear(); }

  bool Eval(Memory*, const dwarf_loc_regs_t&, Regs*) {
    return true;
  }

 protected:
  Memory* regular_memory_;
  DwarfError last_error_;

  std::unordered_map<uint64_t, DwarfFDE> fde_entries_;
  std::unordered_map<uint64_t, DwarfCIE> cie_entries_;
  std::unordered_map<uint64_t, dwarf_loc_regs_t> cie_loc_regs_;
};

template <typename AddressType>
class Dwarf : public DwarfBase {
 public:
  Dwarf(Memory* dwarf_memory, Memory* regular_memory)
    : DwarfBase(regular_memory), memory_(dwarf_memory) {}
  virtual ~Dwarf() = default;

  bool GetMemoryOffset() { return memory_.cur_offset(); }
  void SetMemoryOffset(bool offset) { memory_.set_cur_offset(offset); }

  bool GetCIE(uint64_t offset, DwarfCIE* cie_entry) {
    memory_.set_cur_offset(offset);
    uint32_t length32;
    if (!memory_.ReadBytes(&length32, sizeof(length32))) {
      return false;
    }
    if (length32 == static_cast<uint32_t>(-1)) {
      // 64 bit CIE
      uint64_t length64;
      if (!memory_.ReadBytes(&length64, sizeof(length64))) {
        return false;
      }

      cie_entry->cfa_instructions_end = memory_.cur_offset() + length64;
      cie_entry->fde_address_encoding = DW_EH_PE_sdata8;

      uint64_t cie_id;
      if (!memory_.ReadBytes(&cie_id, sizeof(cie_id))) {
        return false;
      }
      if (cie_id != 0) {
        // This is not a CIE, something has gone horribly wrong.
        return false;
      }
    } else {
      // 32 bit CIE
      cie_entry->cfa_instructions_end = memory_.cur_offset() + length32;
      cie_entry->fde_address_encoding = DW_EH_PE_sdata4;

      uint32_t cie_id;
      if (!memory_.ReadBytes(&cie_id, sizeof(cie_id))) {
        return false;
      }
      if (cie_id != 0) {
        // This is not a CIE, something has gone horribly wrong.
        return false;
      }
    }

    if (!memory_.ReadBytes(&cie_entry->version, sizeof(cie_entry->version))) {
      return false;
    }

    if (cie_entry->version != 1 && cie_entry->version != 3 && cie_entry->version != 4) {
      // Unrecognized version.
      return false;
    }

    // Read the augmentation string.
    char aug_value;
    do {
      if (!memory_.ReadBytes(&aug_value, 1)) {
        return false;
      }
      cie_entry->augmentation_string.push_back(aug_value);
    } while (aug_value != '\0');

    if (cie_entry->version == 4) {
      // Skip the Address Size field since we only use it for validation.
      memory_.set_cur_offset(memory_.cur_offset() + 1);

      // Segment Size
      if (!memory_.ReadBytes(&cie_entry->segment_size, 1)) {
        return false;
      }
    }

    // Code Alignment Factor
    if (!memory_.ReadULEB128(&cie_entry->code_alignment_factor)) {
      return false;
    }

    // Data Alignment Factor
    if (!memory_.ReadSLEB128(&cie_entry->data_alignment_factor)) {
      return false;
    }

    if (cie_entry->version == 1) {
      // Return Address is a single byte.
      uint8_t return_address_register;
      if (!memory_.ReadBytes(&return_address_register, 1)) {
        return false;
      }
      cie_entry->return_address_register = return_address_register;
    } else if (!memory_.ReadULEB128(&cie_entry->return_address_register)) {
      return false;
    }

    if (cie_entry->augmentation_string.size() > 0 && cie_entry->augmentation_string[0] == 'z') {
      uint64_t aug_length;
      if (!memory_.ReadULEB128(&aug_length)) {
        return false;
      }
      cie_entry->cfa_instructions_offset = memory_.cur_offset() + aug_length;

      for (size_t i = 1; i < cie_entry->augmentation_string.size(); i++) {
        switch (cie_entry->augmentation_string[i]) {
        case 'L':
          if (!memory_.ReadBytes(&cie_entry->lsda_encoding, 1)) {
            return false;
          }
          break;
        case 'P':
          {
            uint8_t encoding;
            if (!memory_.ReadBytes(&encoding, 1)) {
              return false;
            }
            if (!memory_.ReadEncodedValue(encoding, &cie_entry->personality_handler)) {
              return false;
            }
          }
          break;
        case 'R':
          if (!memory_.ReadBytes(&cie_entry->fde_address_encoding, 1)) {
            return false;
          }
          break;
        }
      }
    } else {
      cie_entry->cfa_instructions_offset = memory_.cur_offset();
    }

    cie_entries_[offset] = *cie_entry;
    return true;
  }

  bool GetEntryData(uint64_t offset, DwarfCIE* cie_entry, DwarfFDE* fde_entry) {
    auto fde = fde_entries_.find(offset);
    if (fde != fde_entries_.end()) {
      *fde_entry = fde->second;
      auto cie = cie_entries_.find(fde_entry->cie_offset);
      if (cie == cie_entries_.end()) {
        *cie_entry = cie->second;
      } else if (!GetCIE(fde_entry->cie_offset, cie_entry)) {
        return false;
      }
      return true;
    }

    memory_.set_cur_offset(offset);
    uint32_t length32;
    if (!memory_.ReadBytes(&length32, sizeof(length32))) {
      return false;
    }

    uint64_t cur_offset;
    if (length32 == static_cast<uint32_t>(-1)) {
      // 64 bit FDE.
      uint64_t length64;
      if (!memory_.ReadBytes(&length64, sizeof(length64))) {
        return false;
      }
      fde_entry->cfa_instructions_end = memory_.cur_offset() + length64;

      uint64_t value64;
      if (!memory_.ReadBytes(&value64, sizeof(value64))) {
        return false;
      }
      if (value64 == 0) {
        // This is a CIE, this means something has gone wrong.
        return false;
      }

      // Get the CIE pointer, which is necessary to properly read the rest of
      // of the FDE information.
      cur_offset = memory_.cur_offset();
      fde_entry->cie_offset = cur_offset - value64 - 8;
    } else {
      // 32 bit FDE.
      fde_entry->cfa_instructions_end = memory_.cur_offset() + length32;

      uint32_t value32;
      if (!memory_.ReadBytes(&value32, sizeof(value32))) {
        return false;
      }
      if (value32 == 0) {
        // This is a CIE, this means something has gone wrong.
        return false;
      }

      // Get the CIE pointer, which is necessary to properly read the rest of
      // of the FDE information.
      cur_offset = memory_.cur_offset();
      fde_entry->cie_offset = cur_offset - value32 - 4;
    }

    auto entry = cie_entries_.find(fde_entry->cie_offset);
    if (entry != cie_entries_.end()) {
      *cie_entry = entry->second;
    } else if (!GetCIE(fde_entry->cie_offset, cie_entry)) {
      return false;
    }

    if (cie_entry->segment_size != 0) {
      // Skip over the segment selector for now.
      cur_offset += cie_entry->segment_size;
    }
    memory_.set_cur_offset(cur_offset);

    if (!memory_.ReadEncodedValue(cie_entry->fde_address_encoding & 0xf, &fde_entry->start_pc)) {
      return false;
    }
    // This is a relative offset.
    fde_entry->start_pc += cur_offset;

    if (!memory_.ReadEncodedValue(cie_entry->fde_address_encoding & 0xf, &fde_entry->pc_length)) {
      return false;
    }
    if (cie_entry->augmentation_string.size() > 0 && cie_entry->augmentation_string[0] == 'z') {
      // Augmentation Size
      uint64_t aug_length;
      if (!memory_.ReadULEB128(&aug_length)) {
        return false;
      }
      uint64_t cur_offset = memory_.cur_offset();

      if (!memory_.ReadEncodedValue(cie_entry->lsda_encoding, &fde_entry->lsda_address)) {
        return false;
      }

      // Set our position to after all of the augmentation data.
      memory_.set_cur_offset(cur_offset + aug_length);
    }
    fde_entry->cfa_instructions_offset = memory_.cur_offset();

    return true;
  }

  virtual bool GetFdeOffset(uint64_t pc, uint64_t* fde_offset) = 0;

  bool GetCfaLocationInfo(uint64_t pc, dwarf_loc_regs_t* loc_regs) {
    uint64_t fde_offset;
    if (!GetFdeOffset(pc, &fde_offset)) {
      return false;
    }

    DwarfCIE cie;
    DwarfFDE fde;
    if (!GetEntryData(fde_offset, &cie, &fde)) {
      return false;
    }
    return GetCfaLocationInfo(pc, &cie, &fde, loc_regs);
  }

  bool GetCfaLocationInfo(uint64_t pc, DwarfCIE* cie, DwarfFDE* fde, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa<AddressType> cfa(&memory_, cie, fde);

    // Look for the cached copy of the cie data.
    auto reg_entry = cie_loc_regs_.find(fde->cie_offset);
    if (reg_entry == cie_loc_regs_.end()) {
      if (!cfa.GetLocationInfo(pc, cie->cfa_instructions_offset, cie->cfa_instructions_end, loc_regs)) {
        return false;
      }
      cie_loc_regs_[fde->cie_offset] = *loc_regs;
    }
    cfa.set_cie_loc_regs(&cie_loc_regs_[fde->cie_offset]);
    return cfa.GetLocationInfo(pc, fde->cfa_instructions_offset,
                               fde->cfa_instructions_end, loc_regs);
  }

  bool Log(uint8_t indent, uint64_t pc, DwarfCIE* cie, DwarfFDE* fde) {
    DwarfCfa<AddressType> cfa(&memory_, cie, fde);

    // Always print the cie information.
    if (!cfa.Log(indent, pc, cie->cfa_instructions_offset, cie->cfa_instructions_end)) {
      return false;
    }
    return cfa.Log(indent, pc, fde->cfa_instructions_offset, fde->cfa_instructions_end);
  }

#if 0
  bool SetReg(uint8_t reg, Regs<AddressType>* regs, const dwarf_loc_regs_t& loc_regs) {
    
  }
#endif

  void ClearCache() { DwarfBase::ClearCache(); fdes_.clear(); }

 protected:
  DwarfMemory<AddressType> memory_;

  size_t fde_count_ = 0;
  size_t table_entry_size_ = 0;
  std::unordered_map<size_t, FdeInfo> fdes_;
};

class Dwarf32 : public Dwarf<uint32_t> {
 public:
  Dwarf32(Memory* dwarf_memory, Memory* regular_memory)
    : Dwarf(dwarf_memory, regular_memory) { }
  virtual ~Dwarf32() = default;
};

class Dwarf64 : public Dwarf<uint64_t> {
 public:
  Dwarf64(Memory* dwarf_memory, Memory* regular_memory)
    : Dwarf(dwarf_memory, regular_memory) { }
  virtual ~Dwarf64() = default;
};

#endif  // _LIBANDROID_UNWIND_DWARF_H
