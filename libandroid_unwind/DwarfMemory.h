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

#include "DwarfEncoding.h"

template <typename AddressType>
class DwarfMemory {
 public:
  DwarfMemory(Memory* memory, uint64_t offset, uint64_t max_offset) : memory_(memory), cur_offset_(offset), max_offset_(max_offset) {}
  DwarfMemory(Memory* memory, AddressType offset) : memory_(memory), cur_offset_(offset), max_offset_(static_cast<uint64_t>(-1)) {}
  virtual ~DwarfMemory() = default;

  bool ReadBytes(void* dst, size_t num_bytes) {
    if (num_bytes + cur_offset_ > max_offset_ && !memory_->Read(cur_offset_, dst, num_bytes)) {
      return false;
    }
    cur_offset_ += num_bytes;
    return true;
  }

  bool ReadULEB128(uint64_t* value) {
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

  bool ReadSLEB128(uint64_t* value) {
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

  template <typename SignedType>
  bool ReadSigned(uint64_t* value) {
    SignedType signed_value;
    if (!ReadBytes(&signed_value, sizeof(SignedType))) {
      return false;
    }
    // Sign extend the value.
    if (sizeof(AddressType) == 4) {
      *value = static_cast<int32_t>(signed_value);
    } else {
      *value = static_cast<int64_t>(signed_value);
    }
    return true;
  }

  bool ReadEncodedValue(uint8_t encoding, uint64_t* value, uint64_t pc_offset,
                        uint64_t data_offset, uint64_t func_offset, uint64_t text_offset) {
    if (encoding == DW_EH_PE_omit) {
      *value = 0;
      return true;
    }

    // Get the data.
    switch (encoding & 0x0f) {
    case DW_EH_PE_absptr:
      if (!ReadBytes(value, sizeof(AddressType))) {
        return false;
      }
      if (sizeof(AddressType) == 4) {
        // Sign extend.
        *value = static_cast<int32_t>(*value);
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
    case DW_EH_PE_udata1:
      {
        uint8_t value8;
        if (!ReadBytes(&value8, 1)) {
          return false;
        }
        *value = value8;
      }
      break;
    case DW_EH_PE_sdata1:
      if (!ReadSigned<int8_t>(value)) {
        return false;
      }
      break;
    case DW_EH_PE_udata2:
      {
        uint16_t value16;
        if (!ReadBytes(&value16, 2)) {
          return false;
        }
        *value = value16;
      }
      break;
    case DW_EH_PE_sdata2:
      if (!ReadSigned<int16_t>(value)) {
        return false;
      }
      break;
    case DW_EH_PE_udata4:
      {
        uint32_t value32;
        if (!ReadBytes(&value32, 4)) {
          return false;
        }
        *value = value32;
      }
      break;
    case DW_EH_PE_sdata4:
      if (!ReadSigned<int32_t>(value)) {
        return false;
      }
      break;
    case DW_EH_PE_udata8:
      if (!ReadBytes(&value, sizeof(uint64_t))) {
        return false;
      }
      break;
    case DW_EH_PE_sdata8:
      if (!ReadSigned<int64_t>(value)) {
        return false;
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
      if (pc_offset == static_cast<uint64_t>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += pc_offset;
      break;
    case DW_EH_PE_textrel:
      if (text_offset == static_cast<uint64_t>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += text_offset;
      break;
    case DW_EH_PE_datarel:
      if (data_offset == static_cast<uint64_t>(-1)) {
        // Unsupported encoding.
        return false;
      }
      *value += data_offset;
      break;
    case DW_EH_PE_funcrel:
      if (func_offset == static_cast<uint64_t>(-1)) {
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

  bool ReadEntryLength(uint64_t* length) {
    uint32_t value;
    if (!ReadBytes(&value, sizeof(value))) {
      return false;
    }
    if (value == static_cast<uint32_t>(-1)) {
      if (!ReadBytes(length, sizeof(*length))) {
        return false;
      }
    } else {
      *length = value;
    }
    return true;
  }

  uint64_t cur_offset() { return cur_offset_; }
  void set_cur_offset(uint64_t cur_offset) { cur_offset_ = cur_offset; }

 private:
  Memory* memory_;
  uint64_t cur_offset_;
  uint64_t max_offset_;
};

#endif  // _LIBANDROID_UNWIND_DWARF_MEMORY_H
