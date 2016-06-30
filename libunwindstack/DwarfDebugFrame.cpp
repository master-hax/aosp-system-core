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

#include <stdint.h>

#include <algorithm>

#include "DwarfDebugFrame.h"
#include "DwarfMemory.h"
#include "DwarfSection.h"
#include "DwarfStructs.h"
#include "Memory.h"

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::Init(uint64_t offset, uint64_t size) {
  offset_ = offset;
  end_offset_ = offset + size;

  memory_.clear_func_offset();
  memory_.clear_text_offset();
  memory_.set_data_offset(offset);
  memory_.set_cur_offset(offset);

  return CreateSortedFDEList();
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::GetCIEInfo(uint8_t* segment_size, uint8_t* encoding) {
  uint8_t version;
  if (!memory_.ReadBytes(&version, 1)) {
    return false;
  }
  // Read the augmentation string.
  std::vector<char> aug_string;
  char aug_value;
  do {
    if (!memory_.ReadBytes(&aug_value, 1)) {
      return false;
    }
    aug_string.push_back(aug_value);
  } while (aug_value != '\0');

  if (version == 4) {
    // Skip the Address Size field.
    memory_.set_cur_offset(memory_.cur_offset() + 1);

    // Read the segment size.
    if (!memory_.ReadBytes(segment_size, 1)) {
      return false;
    }
  }

  if (aug_string[0] != 'z') {
    // No encoding
    return true;
  }

  // Skip code alignment factor
  uint8_t value;
  do {
    if (!memory_.ReadBytes(&value, 1)) {
      return false;
    }
  } while (value & 0x80);

  // Skip data alignment factor
  do {
    if (!memory_.ReadBytes(&value, 1)) {
      return false;
    }
  } while (value & 0x80);

  if (version == 1) {
    // Skip return address register.
    memory_.set_cur_offset(memory_.cur_offset() + 1);
  } else {
    // Skip return address register.
    do {
      if (!memory_.ReadBytes(&value, 1)) {
        return false;
      }
    } while (value & 0x80);
  }

  // Process the augmentation string.
  if (aug_string[0] == 'z') {
    // Skip the augmentation length.
    do {
      if (!memory_.ReadBytes(&value, 1)) {
        return false;
      }
    } while (value & 0x80);

    for (size_t i = 1; i < aug_string.size(); i++) {
      if (aug_string[i] == 'R') {
        if (!memory_.ReadBytes(encoding, 1)) {
          return false;
        }
        break;
      } else if (aug_string[i] == 'L') {
        memory_.set_cur_offset(memory_.cur_offset() + 1);
      } else if (aug_string[i] == 'P') {
        uint8_t encoding;
        if (!memory_.ReadBytes(&encoding, 1)) {
          return false;
        }
        uint64_t value;
        if (!memory_.template ReadEncodedValue<AddressType>(encoding, &value)) {
          return false;
        }
      }
    }
  }

  return true;
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::AddFDEInfo(
    uint64_t entry_offset, uint8_t segment_size, uint8_t encoding) {
  if (segment_size != 0) {
    memory_.set_cur_offset(memory_.cur_offset() + 1);
  }

  uint64_t start;
  if (!memory_.template ReadEncodedValue<AddressType>(encoding & 0xf, &start)) {
    return false;
  }

  uint64_t length;
  if (!memory_.template ReadEncodedValue<AddressType>(encoding & 0xf, &length)) {
    return false;
  }
  if (length != 0) {
    fdes_.emplace_back(entry_offset, start, length);
  }

  return true;
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::CreateSortedFDEList() {
  memory_.set_cur_offset(offset_);

  // Loop through all of the entries and read just enough to create
  // a sorted list of pcs.
  // This code assumes that first comes the CIE, then the fdes that
  // it applies to.
  uint64_t cie_offset = 0;
  uint8_t address_encoding = 0;
  uint8_t segment_size = 0;
  while (memory_.cur_offset() < end_offset_) {
    uint64_t cur_entry_offset = memory_.cur_offset();

    // Figure out the entry length and type.
    uint32_t value32;
    if (!memory_.ReadBytes(&value32, sizeof(value32))) {
      return false;
    }

    uint64_t next_entry_offset;
    if (value32 == static_cast<uint32_t>(-1)) {
      uint64_t value64;
      if (!memory_.ReadBytes(&value64, sizeof(value64))) {
        return false;
      }
      next_entry_offset = memory_.cur_offset() + value64;

      // Read the CIE Id of a CIE or the pointer of the FDE.
      if (!memory_.ReadBytes(&value64, sizeof(value64))) {
        return false;
      }

      if (value64 == static_cast<uint64_t>(-1)) {
        // CIE 64 bit
        address_encoding = DW_EH_PE_sdata8;
        if (!GetCIEInfo(&segment_size, &address_encoding)) {
          return false;
        }
        cie_offset = cur_entry_offset;
      } else {
        if (offset_ + value64 != cie_offset) {
          // This means that this FDE is not following the CIE.
          return false;
        }

        // FDE 64 bit
        if (!AddFDEInfo(cur_entry_offset, segment_size, address_encoding)) {
          return false;
        }
      }
    } else {
      next_entry_offset = memory_.cur_offset() + value32;

      // Read the CIE Id of a CIE or the pointer of the FDE.
      if (!memory_.ReadBytes(&value32, sizeof(value32))) {
        return false;
      }

      if (value32 == static_cast<uint32_t>(-1)) {
        // CIE 32 bit
        address_encoding = DW_EH_PE_sdata4;
        if (!GetCIEInfo(&segment_size, &address_encoding)) {
          return false;
        }
        cie_offset = cur_entry_offset;
      } else {
        if (offset_ + value32 != cie_offset) {
          // This means that this FDE is not following the CIE.
          return false;
        }

        // FDE 32 bit
        if (!AddFDEInfo(cur_entry_offset, segment_size, address_encoding)) {
          return false;
        }
      }
    }

    if (next_entry_offset < memory_.cur_offset()) {
      // This indicates some kind of corruption, or malformed section data.
      return false;
    }
    memory_.set_cur_offset(next_entry_offset);
  }

  // Sort the entries.
  std::sort(fdes_.begin(), fdes_.end(), [](const FDEInfo& a, const FDEInfo& b) {
    if (a.start == b.start) return a.end < b.end;
    return a.start < b.start;
  });

  fde_count_ = fdes_.size();

  return true;
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::GetFDEOffsetFromPc(uint64_t pc, uint64_t* fde_offset) {
  if (fde_count_ == 0) {
    return false;
  }

  size_t first = 0;
  size_t last = fde_count_;
  while (first < last) {
    size_t current = first + (last - 1 - first) / 2;
    const FDEInfo* info = &fdes_[current];
    if (pc >= info->start && pc <= info->end) {
      *fde_offset = info->offset;
      return true;
    }

    if (pc < info->start) {
      last = current;
    } else {
      first = current + 1;
    }
  }
  return false;
}

template <typename AddressType>
const DwarfFDE* DwarfDebugFrame<AddressType>::GetFDEFromIndex(size_t index) {
  if (index >= fdes_.size()) {
    return nullptr;
  }
  return this->GetFDEFromOffset(fdes_[index].offset);
}

// Explicitly instantiate DwarfDebugFrame.
template class DwarfDebugFrame<uint32_t>;
template class DwarfDebugFrame<uint64_t>;
