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

#ifndef _LIBANDROID_UNWIND_DWARF_CFA_H
#define _LIBANDROID_UNWIND_DWARF_CFA_H

#include <stdint.h>
#include <inttypes.h>

#include <string>
#include <vector>

#include <android-base/stringprintf.h>

#include "DwarfError.h"
#include "DwarfMemory.h"
#include "Memory.h"
#include "Log.h"

class DwarfCfaBase;

struct DwarfCfaCallback {
  bool (*handle_func)(DwarfCfaBase*);
  uint8_t supported_version;
  uint8_t num_operands;
  uint8_t operands[2];
};

extern const DwarfCfaCallback g_cfa_table[64];

enum DwarfCfaDisplayType : uint8_t {
  DWARF_DISPLAY_REGISTER,
  DWARF_DISPLAY_NUMBER,
  DWARF_DISPLAY_SIGNED_NUMBER,
  DWARF_DISPLAY_EVAL_BLOCK,
  DWARF_DISPLAY_ADDRESS,
};

struct DwarfCfaLogInfo {
  const char* name;
  uint8_t operands[2];
};
extern const DwarfCfaLogInfo g_cfa_info[64];

class DwarfCfaBase {
 public:
  DwarfCfaBase(Memory* regular_memory) : regular_memory_(regular_memory) { }
  virtual ~DwarfCfaBase() = default;

  DwarfError last_error() { return last_error_; }

  virtual bool Eval(uint64_t start_offset, uint64_t last_offset) = 0;

 protected:
  Memory* regular_memory_;
  DwarfError last_error_;
};

template <typename AddressType>
class DwarfCfa : public DwarfCfaBase {
 public:
  DwarfCfa(DwarfMemory<AddressType>* memory, Memory* regular_memory)
    : DwarfCfaBase(regular_memory), memory_(memory) { }
  virtual ~DwarfCfa() = default;

  bool Eval(uint64_t start_offset, uint64_t last_offset) override {
    last_error_ = DWARF_ERROR_NONE;
    memory_->set_cur_offset(start_offset);
    uint64_t cfa_offset;
    while ((cfa_offset = memory_->cur_offset()) < last_offset) {
      // Read the cfa information.
      uint8_t cfa_value;
      if (!memory_->ReadBytes(&cfa_value, 1)) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
      // Check the 2 high bits.
      uint8_t cfa_low = cfa_value & 0x3f;
      switch (cfa_value >> 6) {
      case 1:
        if (g_LoggingEnabled) {
          log("Raw Data: 0x%02x", cfa_value);
          log("DW_CFA_advance_loc %d", cfa_low);
        }
        break;
      case 2:
        uint64_t offset;
        if (!memory_->ReadULEB128(&offset)) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
        if (g_LoggingEnabled) {
          log("Raw Data: 0x%02x 0x%02x", cfa_value, offset);
          log("DW_CFA_offset register(%d) %" PRId64, cfa_low, offset);
        }
        break;
      case 3:
        if (g_LoggingEnabled) {
          log("Raw Data: 0x%02x", cfa_value);
          log("DW_CFA_restore register(%d)", cfa_low);
        }
        break;
      case 0:
        {
          const DwarfCfaCallback* cfa = &g_cfa_table[cfa_low];
          if (cfa->handle_func == nullptr) {
            if (g_LoggingEnabled) {
              log("Raw Data: 0x%02x", cfa_value);
              log("Illegal");
            }
            return false;
          }

          std::string log_string;
          if (g_LoggingEnabled) {
            log_string = g_cfa_info[cfa_low].name;
          }

          for (size_t i = 0; i < cfa->num_operands; i++) {
            if (cfa->operands[i] == DW_EH_PE_block) {
              uint64_t block_length;
              if (!memory_->ReadULEB128(&block_length)) {
                return false;
              }
              operands_.push_back(block_length);
              if (g_LoggingEnabled) {
                log_string += " Expression Data";
              }
              memory_->set_cur_offset(memory_->cur_offset() + block_length);
              continue;
            }
            uint64_t value;
            if (!memory_->ReadEncodedValue(cfa->operands[i], &value, static_cast<AddressType>(-1),
                                          static_cast<AddressType>(-1), static_cast<AddressType>(-1),
                                          static_cast<AddressType>(-1))) {
              return false;
            }
            if (g_LoggingEnabled) {
              switch (g_cfa_info[cfa_low].operands[i]) {
              case DWARF_DISPLAY_REGISTER:
                log_string += " register(" + std::to_string(value) + ")";
                break;
              case DWARF_DISPLAY_SIGNED_NUMBER:
                log_string += " ";
                if (sizeof(AddressType) == 4) {
                  log_string += std::to_string(static_cast<int32_t>(value));
                } else {
                  log_string += std::to_string(static_cast<int64_t>(value));
                }
                break;
              case DWARF_DISPLAY_NUMBER:
                log_string += " " + std::to_string(value);
                break;
              case DWARF_DISPLAY_ADDRESS:
                log_string += android::base::StringPrintf(" 0x%" PRIx64, static_cast<uint64_t>(value));
                break;
              }
            }
            operands_.push_back(value);
          }

          if (g_LoggingEnabled) {
            uint64_t cur_offset = memory_->cur_offset();

            std::string raw_data = "Raw Data:";
            memory_->set_cur_offset(cfa_offset);
            for (uint64_t i = 0; i < cur_offset - cfa_offset; i++) {
              uint8_t value;
              if (!memory_->ReadBytes(&value, 1)) {
                return false;
              }

              if (((i + 1) % 10) == 0) {
                log("%s", raw_data.c_str());
                raw_data = "Raw Data:";
              }
              raw_data += android::base::StringPrintf(" 0x%02x", value);
            }
            if (((cur_offset - cfa_offset + 1) % 10) != 0) {
              log("%s", raw_data.c_str());
            }
            log("%s", log_string.c_str());
          }
          if (!cfa->handle_func(this)) {
            return false;
          }
        }
        break;
      }
    }
    return true;
  }

 private:
  std::vector<AddressType> reg_loc_;
  std::vector<AddressType> operands_;

  DwarfMemory<AddressType>* memory_;
};

#endif  // _LIBANDROID_UNWIND_DWARF_CFA_H
