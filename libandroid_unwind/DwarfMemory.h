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

#ifndef _LIBANDROID_UNWIND_DWARF_MEMORY_H
#define _LIBANDROID_UNWIND_DWARF_MEMORY_H

#include <stdint.h>

#include <string>

#include "Memory.h"

enum DwarfEncoding : uint8_t {
  DW_EH_PE_omit = 0xff,

  DW_EH_PE_absptr = 0x00,
  DW_EH_PE_uleb128 = 0x01,
  DW_EH_PE_udata2 = 0x02,
  DW_EH_PE_udata4 = 0x03,
  DW_EH_PE_udata8 = 0x04,
  DW_EH_PE_sleb128 = 0x09,
  DW_EH_PE_sdata2 = 0x0a,
  DW_EH_PE_sdata4 = 0x0b,
  DW_EH_PE_sdata8 = 0x0c,

  DW_EH_PE_pcrel = 0x10,
  DW_EH_PE_textrel = 0x20,
  DW_EH_PE_datarel = 0x30,
  DW_EH_PE_funcrel = 0x40,
  DW_EH_PE_aligned = 0x50,
};

template <typename AddressType>
class DwarfMemory {
 public:
  DwarfMemory(Memory* memory, umaxptr_t offset) : memory_(memory), cur_offset_(offset) {}
  virtual ~DwarfMemory() = default;

  bool ReadBytes(void* dst, size_t num_bytes) {
    if (!memory_->Read(cur_offset_, dst, num_bytes)) {
      return false;
    }
    cur_offset_ += num_bytes;
    return true;
  }

  bool ReadULEB128(AddressType* value) {
    uint64_t cur_value = 0;
    uint64_t shift = 0;
    uint8_t byte;
    do {
      if (!ReadBytes(&byte, 1)) {
        return false;
      }
      cur_value += static_cast<uint64_t>(byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    *value = cur_value;
    return true;
  }

  bool ReadSLEB128(AddressType* value) {
    uint64_t cur_value = 0;
    uint64_t shift = 0;
    uint8_t byte;
    do {
      if (!ReadBytes(&byte, 1)) {
        return false;
      }
      cur_value += static_cast<uint64_t>(byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    if (byte & 0x40) {
      // Negative value, need to sign extend.
      cur_value |= static_cast<uint64_t>(-1) << shift;
    }
    *value = cur_value;
    return true;
  }

  bool ReadEncodedValue(uint8_t encoding, AddressType* value, AddressType pc_offset, AddressType data_offset, AddressType func_offset, AddressType text_offset) {
    if (encoding == DW_EH_PE_omit) {
      *value = 0;
      return true;
    }

    // Get the data.
    switch (encoding & 0x0f) {
    case DW_EH_PE_absptr:
      if (!ReadBytes(value, sizeof(*value))) {
        return false;
      }
      break;
    case DW_EH_PE_uleb128:
      if (!ReadULEB128(value)) {
        return false;
      }
      break;
    case DW_EH_PE_sleb128:
      if (!ReadSLEB128(value)) {
        return false;
      }
      break;
    case DW_EH_PE_udata2:
      if (!ReadBytes(value, 2)) {
        return false;
      }
      break;
    case DW_EH_PE_sdata2:
      if (!ReadBytes(value, 2)) {
        return false;
      }
      break;
    case DW_EH_PE_udata4:
      if (!ReadBytes(value, 4)) {
        return false;
      }
      break;
    case DW_EH_PE_sdata4:
      if (!ReadBytes(value, 4)) {
        return false;
      }
      break;
    case DW_EH_PE_udata8:
      {
        uint64_t value64;
        if (!ReadBytes(&value64, sizeof(uint64_t))) {
          return false;
        }
        *value = value64;
      }
      break;
    case DW_EH_PE_sdata8:
      {
        uint64_t value64;
        if (!ReadBytes(&value64, sizeof(uint64_t))) {
          return false;
        }
        *value = value64;
      }
      break;
    default:
      return false;
    }

    // Handle the encoding.
    switch (encoding & 0xf0) {
    case DW_EH_PE_absptr:
      // Nothing to do.
      break;
    case DW_EH_PE_pcrel:
      if (pc_offset == static_cast<AddressType>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += pc_offset;
      break;
    case DW_EH_PE_textrel:
      if (text_offset == static_cast<AddressType>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += text_offset;
      break;
    case DW_EH_PE_datarel:
      if (data_offset == static_cast<AddressType>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += data_offset;
      break;
    case DW_EH_PE_funcrel:
      if (func_offset == static_cast<AddressType>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += func_offset;
      break;
    case DW_EH_PE_aligned:
      *value = (*value + (sizeof(AddressType) - 1)) & ~((sizeof(AddressType) - 1));
      break;
    default:
      return false;
    }

    return true;
  }

  umaxptr_t cur_offset() { return cur_offset_; }

 private:
  Memory* memory_;
  umaxptr_t cur_offset_;
};

#endif  // _LIBANDROID_UNWIND_DWARF_MEMORY_H
