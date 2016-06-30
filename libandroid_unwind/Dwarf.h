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
#include "DwarfOp.h"
#include "Memory.h"

struct DwarfCIE {
  uint8_t version = 0;
  uint8_t fde_address_encoding = DW_EH_PE_absptr;
  uint8_t lsda_encoding = DW_EH_PE_omit;
  uint8_t segment_size = 0;
  std::vector<char> augmentation_string;
  uint64_t personality_handler = 0;
  uint64_t cfa_instructions_offset = 0;
  uint64_t cfa_instructions_end = 0;
  uint64_t code_alignment_factor = 0;
  uint64_t data_alignment_factor = 0;
  uint64_t return_address_register = 0;
};

struct DwarfFDE {
  uint64_t cie_offset = 0;
  uint64_t cfa_instructions_offset = 0;
  uint64_t cfa_instructions_end = 0;
  uint64_t start_ip = 0;
  uint64_t ip_length = 0;
  uint64_t lsda_address = 0;
};

class DwarfBase {
 public:
  DwarfBase(Memory* regular_memory) : regular_memory_(regular_memory) { }
  virtual ~DwarfBase() = default;

  DwarfError last_error() { return last_error_; }

 protected:
  Memory* regular_memory_;
  DwarfError last_error_;

  std::unordered_map<uint64_t, DwarfCIE> cie_entries_;
  std::unordered_map<uint64_t, DwarfFDE> fde_entries_;
};

template <typename AddressType>
class Dwarf : public DwarfBase {
 public:
  Dwarf(DwarfMemory<AddressType>* memory, Memory* regular_memory)
    : DwarfBase(regular_memory), memory_(memory), cfa_(memory, regular_memory), op_(memory, regular_memory) { }
  virtual ~Dwarf() = default;

  bool GetCIE(uint64_t offset, DwarfCIE* cie_entry) {
    memory_->set_cur_offset(offset);
    uint32_t length32;
    if (!memory_->ReadBytes(&length32, sizeof(length32))) {
      return false;
    }
    if (length32 == static_cast<uint32_t>(-1)) {
      // 64 bit CIE
      uint64_t length64;
      if (!memory_->ReadBytes(&length64, sizeof(length64))) {
        return false;
      }

      cie_entry->cfa_instructions_end = memory_->cur_offset() + length64;
      cie_entry->fde_address_encoding = DW_EH_PE_sdata8;

      uint64_t cie_id;
      if (!memory_->ReadBytes(&cie_id, sizeof(cie_id))) {
        return false;
      }
      if (cie_id != 0) {
        // This is not a CIE, something has gone horribly wrong.
        return false;
      }
    } else {
      // 32 bit CIE
      cie_entry->cfa_instructions_end = memory_->cur_offset() + length32;
      cie_entry->fde_address_encoding = DW_EH_PE_sdata4;

      uint32_t cie_id;
      if (!memory_->ReadBytes(&cie_id, sizeof(cie_id))) {
        return false;
      }
      if (cie_id != 0) {
        // This is not a CIE, something has gone horribly wrong.
        return false;
      }
    }

    if (!memory_->ReadBytes(&cie_entry->version, sizeof(cie_entry->version))) {
      return false;
    }

    if (cie_entry->version != 1 && cie_entry->version != 3 && cie_entry->version != 4) {
      // Unrecognized version.
      return false;
    }

    // Read the augmentation string.
    char aug_value;
    do {
      if (!memory_->ReadBytes(&aug_value, 1)) {
        return false;
      }
      cie_entry->augmentation_string.push_back(aug_value);
    } while (aug_value != '\0');

    if (cie_entry->version == 4) {
      // Skip the Address Size field since we only use it for validation.
      memory_->set_cur_offset(memory_->cur_offset() + 1);

      // Segment Size
      if (!memory_->ReadBytes(&cie_entry->segment_size, 1)) {
        return false;
      }
    }

    // Code Alignment Factor
    if (!memory_->ReadULEB128(&cie_entry->code_alignment_factor)) {
      return false;
    }

    // Data Alignment Factor
    if (!memory_->ReadSLEB128(&cie_entry->data_alignment_factor)) {
      return false;
    }

    if (cie_entry->version == 1) {
      // Return Address is a single byte.
      uint8_t return_address_register;
      if (!memory_->ReadBytes(&return_address_register, 1)) {
        return false;
      }
      cie_entry->return_address_register = return_address_register;
    } else if (!memory_->ReadULEB128(&cie_entry->return_address_register)) {
      return false;
    }

    if (cie_entry->augmentation_string.size() > 0 && cie_entry->augmentation_string[0] == 'z') {
      uint64_t aug_length;
      if (!memory_->ReadULEB128(&aug_length)) {
        return false;
      }
      cie_entry->cfa_instructions_offset = memory_->cur_offset() + aug_length;

      for (size_t i = 1; i < cie_entry->augmentation_string.size(); i++) {
        switch (cie_entry->augmentation_string[i]) {
        case 'L':
          if (!memory_->ReadBytes(&cie_entry->lsda_encoding, 1)) {
            return false;
          }
          break;
        case 'P':
          {
            uint8_t encoding;
            if (!memory_->ReadBytes(&encoding, 1)) {
              return false;
            }
            if (!memory_->ReadEncodedValue(encoding, &cie_entry->personality_handler, 0, 0, 0, 0)) {
              return false;
            }
          }
          break;
        case 'R':
          if (!memory_->ReadBytes(&cie_entry->fde_address_encoding, 1)) {
            return false;
          }
          break;
        }
      }
    } else {
      cie_entry->cfa_instructions_offset = memory_->cur_offset();
    }

    cie_entries_[offset] = *cie_entry;
    return true;
  }

  bool GetEntryData(uint64_t offset, DwarfFDE* fde_entry, DwarfCIE* cie_entry) {
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

    memory_->set_cur_offset(offset);
    uint32_t length32;
    if (!memory_->ReadBytes(&length32, sizeof(length32))) {
      return false;
    }

    uint64_t cur_offset;
    if (length32 == static_cast<uint32_t>(-1)) {
      // 64 bit FDE.
      uint64_t length64;
      if (!memory_->ReadBytes(&length64, sizeof(length64))) {
        return false;
      }
      fde_entry->cfa_instructions_end = memory_->cur_offset() + length64;

      uint64_t value64;
      if (!memory_->ReadBytes(&value64, sizeof(value64))) {
        return false;
      }
      if (value64 == 0) {
        // This is a CIE, this means something has gone wrong.
        return false;
      }

      // Get the CIE pointer, which is necessary to properly read the rest of
      // of the FDE information.
      cur_offset = memory_->cur_offset();
      fde_entry->cie_offset = cur_offset - value64 - 8;
    } else {
      // 32 bit FDE.
      fde_entry->cfa_instructions_end = memory_->cur_offset() + length32;

      uint32_t value32;
      if (!memory_->ReadBytes(&value32, sizeof(value32))) {
        return false;
      }
      if (value32 == 0) {
        // This is a CIE, this means something has gone wrong.
        return false;
      }

      // Get the CIE pointer, which is necessary to properly read the rest of
      // of the FDE information.
      cur_offset = memory_->cur_offset();
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
    memory_->set_cur_offset(cur_offset);

    if (!memory_->ReadEncodedValue(cie_entry->fde_address_encoding & 0xf, &fde_entry->start_ip, 0, 0, 0, 0)) {
      return false;
    }
    // This is a relative offset.
    fde_entry->start_ip += cur_offset;

    if (!memory_->ReadEncodedValue(cie_entry->fde_address_encoding & 0xf, &fde_entry->ip_length, 0, 0, 0, 0)) {
      return false;
    }
    if (cie_entry->augmentation_string.size() > 0 && cie_entry->augmentation_string[0] == 'z') {
      // Augmentation Size
      uint64_t aug_length;
      if (!memory_->ReadULEB128(&aug_length)) {
        return false;
      }
      uint64_t cur_offset = memory_->cur_offset();

      if (!memory_->ReadEncodedValue(cie_entry->lsda_encoding, &fde_entry->lsda_address, 0, 0, 0, 0)) {
        return false;
      }

      // Set our position to after all of the augmentation data.
      memory_->set_cur_offset(cur_offset + aug_length);
    }
    fde_entry->cfa_instructions_offset = memory_->cur_offset();

    return true;
  }

  bool EvalCfa(uint64_t start_offset, uint64_t last_offset) {
    return cfa_.Eval(start_offset, last_offset);
  }

 private:
  DwarfMemory<AddressType>* memory_;
  DwarfCfa<AddressType> cfa_;
  DwarfOp<AddressType> op_;
};

class Dwarf32 : public Dwarf<uint32_t> {
 public:
  Dwarf32(DwarfMemory<uint32_t>* memory, Memory* regular_memory)
    : Dwarf(memory, regular_memory) { }
  virtual ~Dwarf32() = default;
};

class Dwarf64 : public Dwarf<uint64_t> {
 public:
  Dwarf64(DwarfMemory<uint64_t>* memory, Memory* regular_memory)
    : Dwarf(memory, regular_memory) { }
  virtual ~Dwarf64() = default;
};

#endif  // _LIBANDROID_UNWIND_DWARF_H
