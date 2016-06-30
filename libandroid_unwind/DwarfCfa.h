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

#include <stdio.h>

#include <stdint.h>
#include <inttypes.h>

#include <memory>
#include <stack>
#include <string>
#include <vector>
#include <unordered_map>

#include <android-base/stringprintf.h>

#include "DwarfError.h"
#include "DwarfLocation.h"
#include "DwarfMemory.h"
#include "DwarfStructs.h"
#include "Memory.h"
#include "Log.h"

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

template <typename AddressType>
class DwarfCfa {
 public:
  DwarfCfa(DwarfMemory<AddressType>* memory, DwarfCIE* cie, DwarfFDE* fde)
    : memory_(memory), cie_(cie), fde_(fde) { }
  virtual ~DwarfCfa() = default;

  bool GetLocationInfo(uint64_t pc, uint64_t start_offset, uint64_t end_offset, dwarf_loc_regs_t* loc_regs) {
    if (cie_loc_regs_ != nullptr) {
      for (const auto& entry : *cie_loc_regs_) {
        (*loc_regs)[entry.first] = entry.second;
      }
    }
    last_error_ = DWARF_ERROR_NONE;

    memory_->set_cur_offset(start_offset);
    uint64_t cfa_offset;
    cur_pc_ = fde_->start_pc;
    while ((cfa_offset = memory_->cur_offset()) < end_offset && cur_pc_ <= pc) {
      operands_.clear();
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
        cur_pc_ += cfa_low * cie_->code_alignment_factor;
        break;
      case 2:
      {
        uint64_t offset;
        if (!memory_->ReadULEB128(&offset)) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
        (*loc_regs)[cfa_low] = { .type = DWARF_LOCATION_OFFSET,
                                 .values = { offset * cie_->data_alignment_factor } };
        break;
      }
      case 3:
      {
        if (cie_loc_regs_ == nullptr) {
          log(0, "restore while processing cie");
          last_error_ = DWARF_ERROR_ILLEGAL_STATE;
          return false;
        }

        auto reg_entry = cie_loc_regs_->find(cfa_low);
        if (reg_entry == cie_loc_regs_->end()) {
          loc_regs->erase(cfa_low);
        } else {
          (*loc_regs)[cfa_low] = reg_entry->second;
        }
        break;
      }
      case 0:
      {
        const auto* cfa = &kCallbackTable[cfa_low];
        if (cfa->handle_func == nullptr) {
          last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
          return false;
        }

        for (size_t i = 0; i < cfa->num_operands; i++) {
          if (cfa->operands[i] == DW_EH_PE_block) {
            uint64_t block_length;
            if (!memory_->ReadULEB128(&block_length)) {
              last_error_ = DWARF_ERROR_MEMORY_INVALID;
              return false;
            }
            operands_.push_back(block_length);
            memory_->set_cur_offset(memory_->cur_offset() + block_length);
            continue;
          }
          uint64_t value;
          if (!memory_->ReadEncodedValue(cfa->operands[i], &value)) {
            last_error_ = DWARF_ERROR_MEMORY_INVALID;
            return false;
          }
          operands_.push_back(value);
        }

        if (!cfa->handle_func(this, loc_regs)) {
          return false;
        }
        break;
      }
      }
    }
    return true;
  }

  std::string GetOperandString(uint8_t operand, uint64_t value) {
    std::string string;
    switch (operand) {
    case DWARF_DISPLAY_REGISTER:
      string = " register(" + std::to_string(value) + ")";
      break;
    case DWARF_DISPLAY_SIGNED_NUMBER:
      string += " ";
      if (sizeof(AddressType) == 4) {
        string += std::to_string(static_cast<int32_t>(value));
      } else {
        string += std::to_string(static_cast<int64_t>(value));
      }
      break;
    case DWARF_DISPLAY_NUMBER:
      string += " " + std::to_string(value);
      break;
    case DWARF_DISPLAY_ADDRESS:
      if (sizeof(AddressType) == 4) {
        string += android::base::StringPrintf(" 0x%" PRIx32, static_cast<uint32_t>(value));
      } else {
        string += android::base::StringPrintf(" 0x%" PRIx64, static_cast<uint64_t>(value));
      }
      break;
    default:
      string = " unknown";
    }
    return string;
  }

  bool LogOffsetRegisterString(uint32_t indent, uint64_t cfa_offset, uint8_t reg) {
    uint64_t offset;
    if (!memory_->ReadULEB128(&offset)) {
      return false;
    }
    uint64_t end_offset = memory_->cur_offset();
    memory_->set_cur_offset(cfa_offset);

    std::string raw_data = "Raw Data:";
    for (uint64_t i = cfa_offset; i < end_offset; i++) {
      uint8_t value;
      if (!memory_->ReadBytes(&value, 1)) {
        return false;
      }
      raw_data += android::base::StringPrintf(" 0x%02x", value);
    }
    log(indent, "%s", raw_data.c_str());
    log(indent, "DW_CFA_offset register(%d) %" PRId64, reg, offset);
    return true;
  }

  bool LogInstruction(uint32_t indent, uint64_t cfa_offset, uint8_t op) {
    const auto* cfa = &kCallbackTable[op];
    if (cfa->handle_func == nullptr) {
      log(indent, "Raw Data: 0x%02x", op);
      log(indent, "Illegal");
      return true;
    }

    std::string log_string(g_cfa_info[op].name);
    for (size_t i = 0; i < cfa->num_operands; i++) {
      if (cfa->operands[i] == DW_EH_PE_block) {
        // This is a Dwarf Expression.
        uint64_t block_length;
        if (!memory_->ReadULEB128(&block_length)) {
          return false;
        }

        log_string += " " + std::to_string(block_length);
        memory_->set_cur_offset(memory_->cur_offset() + block_length);
      } else {
        uint64_t value;
        if (!memory_->ReadEncodedValue(cfa->operands[i], &value)) {
          return false;
        }
        log_string += GetOperandString(g_cfa_info[op].operands[i], value);
      }
    }

    // Get the raw bytes of the data.
    uint64_t end_offset = memory_->cur_offset();
    memory_->set_cur_offset(cfa_offset);
    std::string raw_data("Raw Data:");
    for (uint64_t i = 0; i < end_offset - cfa_offset; i++) {
      uint8_t value;
      if (!memory_->ReadBytes(&value, 1)) {
        return false;
      }

      // Only show 10 raw bytes per line.
      if ((i % 10) == 0 && i != 0) {
        log(indent, "%s", raw_data.c_str());
        raw_data.clear();
      }
      if (raw_data.empty()) {
        raw_data = "Raw Data:";
      }
      raw_data += android::base::StringPrintf(" 0x%02x", value);
    }
    if (!raw_data.empty()) {
      log(indent, "%s", raw_data.c_str());
    }
    log(indent, "%s", log_string.c_str());
    return true;
  }

  bool Log(uint32_t indent, uint64_t pc, uint64_t start_offset, uint64_t end_offset) {
    memory_->set_cur_offset(start_offset);
    uint64_t cfa_offset;
    uint64_t cur_pc = fde_->start_pc;
    while ((cfa_offset = memory_->cur_offset()) < end_offset && cur_pc <= pc) {
      // Read the cfa information.
      uint8_t cfa_value;
      if (!memory_->ReadBytes(&cfa_value, 1)) {
        return false;
      }

      // Check the 2 high bits.
      uint8_t cfa_low = cfa_value & 0x3f;
      switch (cfa_value >> 6) {
      case 0:
        if (!LogInstruction(indent, cfa_offset, cfa_low)) {
          return false;
        }
        break;
      case 1:
        log(indent, "Raw Data: 0x%02x", cfa_value);
        log(indent, "DW_CFA_advance_loc %d", cfa_low);
        cur_pc += cfa_low * cie_->code_alignment_factor;
        break;
      case 2:
        if (!LogOffsetRegisterString(indent, cfa_offset, cfa_low)) {
          return false;
        }
        break;
      case 3:
        log(indent, "Raw Data: 0x%02x", cfa_value);
        log(indent, "DW_CFA_restore register(%d)", cfa_low);
        break;
      }
    }
    return true;
  }

  DwarfError last_error() { return last_error_; }
  AddressType cur_pc() { return cur_pc_; }

  void set_cie_loc_regs(const dwarf_loc_regs_t* cie_loc_regs) { cie_loc_regs_ = cie_loc_regs; }

 private:
  DwarfError last_error_;
  DwarfMemory<AddressType>* memory_;
  DwarfCIE* cie_;
  DwarfFDE* fde_;

  AddressType cur_pc_;
  const dwarf_loc_regs_t* cie_loc_regs_ = nullptr;
  std::vector<AddressType> operands_;
  std::stack<dwarf_loc_regs_t> loc_reg_state_;

  // Static data.
  static bool cfa_nop(void*, dwarf_loc_regs_t*) {
    return true;
  }

  static bool cfa_set_loc(void* ptr, dwarf_loc_regs_t*) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType cur_pc = cfa->cur_pc_;
    AddressType new_pc = cfa->operands_[0];
    if (new_pc < cur_pc) {
      if (sizeof(AddressType) == 4) {
        log(0, "Warning: PC is moving backwards: old 0x%" PRIx32 " new 0x%" PRIx32,
            cur_pc, new_pc);
      } else {
        log(0, "Warning: PC is moving backwards: old 0x%" PRIx64 " new 0x%" PRIx64,
            cur_pc, new_pc);
      }
    }
    cfa->cur_pc_ = new_pc;
    return true;
  }

  static bool cfa_advance_loc(void* ptr, dwarf_loc_regs_t*) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    cfa->cur_pc_ += cfa->operands_[0] * cfa->cie_->code_alignment_factor;
    return true;
  }

  static bool cfa_offset(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    (*loc_regs)[reg] = { .type = DWARF_LOCATION_OFFSET, .values = { cfa->operands_[1] } };
    return true;
  }

  static bool cfa_restore(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    if (cfa->cie_loc_regs_ == nullptr) {
      log(0, "restore while processing cie");
      cfa->last_error_ = DWARF_ERROR_ILLEGAL_STATE;
      return false;
    }
    auto reg_entry = cfa->cie_loc_regs_->find(reg);
    if (reg_entry == cfa->cie_loc_regs_->end()) {
      loc_regs->erase(reg);
    } else {
      (*loc_regs)[reg] = reg_entry->second;
    }
    return true;
  }

  static bool cfa_undefined(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    auto reg_entry = loc_regs->find(reg);
    if (reg_entry != loc_regs->end()) {
      loc_regs->erase(reg);
    }
    return true;
  }

  static bool cfa_same_value(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    (*loc_regs)[reg] = { .type = DWARF_LOCATION_SAME };
    return true;
  }

  static bool cfa_register(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    AddressType reg_dst = cfa->operands_[1];
    (*loc_regs)[reg] = { .type = DWARF_LOCATION_REGISTER, .values = { reg_dst } };
    return true;
  }

  static bool cfa_remember_state(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    cfa->loc_reg_state_.push(*loc_regs);
    return true;
  }

  static bool cfa_restore_state(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    if (cfa->loc_reg_state_.size() == 0) {
      log(0, "Warning: Attempt to restore without remember.");
      return true;
    }
    *loc_regs = cfa->loc_reg_state_.top();
    cfa->loc_reg_state_.pop();
    return true;
  }

  static bool cfa_def_cfa(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER,
                             .values = { cfa->operands_[0], cfa->operands_[1] } };
    return true;
  }

  static bool cfa_def_cfa_register(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER,
                             .values = { cfa->operands_[0], 0 } };
    return true;
  }

  static bool cfa_def_cfa_offset(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    // Changing the offset if this is not a register is illegal.
    auto cfa_location = loc_regs->find(CFA_REG);
    if (cfa_location == loc_regs->end() || cfa_location->second.type != DWARF_LOCATION_REGISTER) {
      log(0, "Attempt to set offset, but cfa is not set to a register.");
      cfa->last_error_ = DWARF_ERROR_ILLEGAL_STATE;
      return false;
    }
    cfa_location->second.values[1] = cfa->operands_[0];
    return true;
  }

  static bool cfa_def_cfa_expression(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_EXPRESSION,
                             .values = { cfa->operands_[0], cfa->memory_->cur_offset() } };
    return true;
  }

  static bool cfa_expression(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    (*loc_regs)[reg] = { .type = DWARF_LOCATION_EXPRESSION,
                         .values = { cfa->operands_[1], cfa->memory_->cur_offset() } };
    return true;
  }

  static bool cfa_offset_extended_sf(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    if (sizeof(AddressType) == 4) {
      int32_t value = cfa->operands_[1] * cfa->cie_->data_alignment_factor;
      (*loc_regs)[reg] = { .type = DWARF_LOCATION_OFFSET,
                           .values = { static_cast<uint64_t>(value) } };
    } else {
      int64_t value = cfa->operands_[1] * cfa->cie_->data_alignment_factor;
      (*loc_regs)[reg] = { .type = DWARF_LOCATION_OFFSET,
                           .values = { static_cast<uint64_t>(value) } };
    }
    return true;
  }

  static bool cfa_def_cfa_sf(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    int64_t offset64;
    if (sizeof(AddressType) == 4) {
      offset64 = static_cast<int32_t>(cfa->operands_[1] * cfa->cie_->data_alignment_factor);
    } else {
      offset64 = cfa->operands_[1] * cfa->cie_->data_alignment_factor;
    }
    (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER,
                             .values = { cfa->operands_[0], static_cast<uint64_t>(offset64) } };
    return true;
  }

  static bool cfa_def_cfa_offset_sf(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    // Changing the offset if this is not a register is illegal.
    auto cfa_location = loc_regs->find(CFA_REG);
    if (cfa_location == loc_regs->end() || cfa_location->second.type != DWARF_LOCATION_REGISTER) {
      log(0, "Attempt to set offset, but cfa is not set to a register.");
      cfa->last_error_ = DWARF_ERROR_ILLEGAL_STATE;
      return false;
    }
    cfa_location->second.values[1] = cfa->operands_[0] * cfa->cie_->data_alignment_factor;
    return true;
  }

  static bool cfa_val_offset(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    (*loc_regs)[reg] = { .type = DWARF_LOCATION_VAL_OFFSET,
                         .values = { cfa->operands_[1] * cfa->cie_->data_alignment_factor } };
    return true;
  }

  static bool cfa_val_offset_sf(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    if (sizeof(AddressType) == 4) {
      int32_t value = static_cast<int32_t>(cfa->operands_[1]) * cfa->cie_->data_alignment_factor;
      (*loc_regs)[reg] = { .type = DWARF_LOCATION_VAL_OFFSET,
                           .values = { static_cast<uint64_t>(value) } };
    } else {
      int64_t value = static_cast<int64_t>(cfa->operands_[1]) * cfa->cie_->data_alignment_factor;
      (*loc_regs)[reg] = { .type = DWARF_LOCATION_VAL_OFFSET,
                           .values = { static_cast<uint64_t>(value) } };
    }
    return true;
  }

  static bool cfa_val_expression(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    (*loc_regs)[reg] = { .type = DWARF_LOCATION_VAL_EXPRESSION,
                         .values = { cfa->operands_[1], cfa->memory_->cur_offset() } };
    return true;
  }

  static bool cfa_gnu_negative_offset_extended(void* ptr, dwarf_loc_regs_t* loc_regs) {
    DwarfCfa* cfa = reinterpret_cast<DwarfCfa*>(ptr);
    AddressType reg = cfa->operands_[0];
    if (sizeof(AddressType) == 4) {
      int32_t value = -cfa->operands_[1];
      (*loc_regs)[reg] = { .type = DWARF_LOCATION_OFFSET,
                           .values = { static_cast<uint64_t>(value) } };
    } else {
      int64_t value = -cfa->operands_[1];
      (*loc_regs)[reg] = { .type = DWARF_LOCATION_OFFSET,
                           .values = { static_cast<uint64_t>(value) } };
    }
    return true;
  }

  constexpr static DwarfLocCallback kCallbackTable[64] = {
    {                           // 0x00 DW_CFA_nop
      cfa_nop,
      2,
      0,
      {},
    },
    {                           // 0x01 DW_CFA_set_loc
      cfa_set_loc,
      2,
      1,
      { DW_EH_PE_absptr },
    },
    {                           // 0x02 DW_CFA_advance_loc1
      cfa_advance_loc,
      2,
      1,
      { DW_EH_PE_udata1 },
    },
    {                           // 0x03 DW_CFA_advance_loc2
      cfa_advance_loc,
      2,
      1,
      { DW_EH_PE_udata2 },
    },
    {                           // 0x04 DW_CFA_advance_loc4
      cfa_advance_loc,
      2,
      1,
      { DW_EH_PE_udata4 },
    },
    {                           // 0x05 DW_CFA_offset_extended
      cfa_offset,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
    },
    {                           // 0x06 DW_CFA_restore_extended
      cfa_restore,
      2,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                           // 0x07 DW_CFA_undefined
      cfa_undefined,
      2,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                           // 0x08 DW_CFA_same_value
      cfa_same_value,
      2,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                           // 0x09 DW_CFA_register
      cfa_register,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
    },
    {                           // 0x0a DW_CFA_remember_state
      cfa_remember_state,
      2,
      0,
      {},
    },
    {                           // 0x0b DW_CFA_restore_state
      cfa_restore_state,
      2,
      0,
      {},
    },
    {                           // 0x0c DW_CFA_def_cfa
      cfa_def_cfa,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
    },
    {                           // 0x0d DW_CFA_def_cfa_register
      cfa_def_cfa_register,
      2,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                           // 0x0e DW_CFA_def_cfa_offset
      cfa_def_cfa_offset,
      2,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                           // 0x0f DW_CFA_def_cfa_expression
      cfa_def_cfa_expression,
      2,
      1,
      { DW_EH_PE_block },
    },
    {                           // 0x10 DW_CFA_expression
      cfa_expression,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_block },
    },
    {                           // 0x11 DW_CFA_offset_extended_sf
      cfa_offset_extended_sf,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_sleb128 },
    },
    {                           // 0x12 DW_CFA_def_cfa_sf
      cfa_def_cfa_sf,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_sleb128 },
    },
    {                           // 0x13 DW_CFA_def_cfa_offset_sf
      cfa_def_cfa_offset_sf,
      2,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                           // 0x14 DW_CFA_val_offset
      cfa_val_offset,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
    },
    {                           // 0x15 DW_CFA_val_offset_sf
      cfa_val_offset_sf,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_sleb128 },
    },
    {                           // 0x16 DW_CFA_val_expression
      cfa_val_expression,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_block },
    },
    { nullptr, 0, 0, {} },      // 0x17 illegal cfa
    { nullptr, 0, 0, {} },      // 0x18 illegal cfa
    { nullptr, 0, 0, {} },      // 0x19 illegal cfa
    { nullptr, 0, 0, {} },      // 0x1a illegal cfa
    { nullptr, 0, 0, {} },      // 0x1b illegal cfa
    { nullptr, 0, 0, {} },      // 0x1c DW_CFA_lo_user (Treat this as illegal)
    { nullptr, 0, 0, {} },      // 0x1d illegal cfa
    { nullptr, 0, 0, {} },      // 0x1e illegal cfa
    { nullptr, 0, 0, {} },      // 0x1f illegal cfa
    { nullptr, 0, 0, {} },      // 0x20 illegal cfa
    { nullptr, 0, 0, {} },      // 0x21 illegal cfa
    { nullptr, 0, 0, {} },      // 0x22 illegal cfa
    { nullptr, 0, 0, {} },      // 0x23 illegal cfa
    { nullptr, 0, 0, {} },      // 0x24 illegal cfa
    { nullptr, 0, 0, {} },      // 0x25 illegal cfa
    { nullptr, 0, 0, {} },      // 0x26 illegal cfa
    { nullptr, 0, 0, {} },      // 0x27 illegal cfa
    { nullptr, 0, 0, {} },      // 0x28 illegal cfa
    { nullptr, 0, 0, {} },      // 0x29 illegal cfa
    { nullptr, 0, 0, {} },      // 0x2a illegal cfa
    { nullptr, 0, 0, {} },      // 0x2b illegal cfa
    { nullptr, 0, 0, {} },      // 0x2c illegal cfa
    { nullptr, 0, 0, {} },      // 0x2d DW_CFA_GNU_window_save (Treat this as illegal)
    {                           // 0x2e DW_CFA_GNU_args_size
      cfa_nop,
      2,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                           // 0x2f DW_CFA_GNU_negative_offset_extended
      cfa_gnu_negative_offset_extended,
      2,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
    },
    { nullptr, 0, 0, {} },      // 0x30 illegal cfa
    { nullptr, 0, 0, {} },      // 0x31 illegal cfa
    { nullptr, 0, 0, {} },      // 0x32 illegal cfa
    { nullptr, 0, 0, {} },      // 0x33 illegal cfa
    { nullptr, 0, 0, {} },      // 0x34 illegal cfa
    { nullptr, 0, 0, {} },      // 0x35 illegal cfa
    { nullptr, 0, 0, {} },      // 0x36 illegal cfa
    { nullptr, 0, 0, {} },      // 0x37 illegal cfa
    { nullptr, 0, 0, {} },      // 0x38 illegal cfa
    { nullptr, 0, 0, {} },      // 0x39 illegal cfa
    { nullptr, 0, 0, {} },      // 0x3a illegal cfa
    { nullptr, 0, 0, {} },      // 0x3b illegal cfa
    { nullptr, 0, 0, {} },      // 0x3c illegal cfa
    { nullptr, 0, 0, {} },      // 0x3d illegal cfa
    { nullptr, 0, 0, {} },      // 0x3e illegal cfa
    { nullptr, 0, 0, {} },      // 0x3f DW_CFA_hi_user (Treat this as illegal)
  };
};
template<typename AddressType> constexpr DwarfLocCallback DwarfCfa<AddressType>::kCallbackTable[64];

#endif  // _LIBANDROID_UNWIND_DWARF_CFA_H
