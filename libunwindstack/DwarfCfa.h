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

#ifndef _LIBUNWINDSTACK_DWARF_CFA_H
#define _LIBUNWINDSTACK_DWARF_CFA_H

#include <stdint.h>

#include <stack>
#include <string>
#include <type_traits>
#include <vector>

#include "DwarfError.h"
#include "DwarfMemory.h"
#include "DwarfStructs.h"

class DwarfCfaInfo {
 public:
  enum DisplayType : uint8_t {
    DWARF_DISPLAY_NONE = 0,
    DWARF_DISPLAY_REGISTER,
    DWARF_DISPLAY_NUMBER,
    DWARF_DISPLAY_SIGNED_NUMBER,
    DWARF_DISPLAY_EVAL_BLOCK,
    DWARF_DISPLAY_ADDRESS,
    DWARF_DISPLAY_SET_LOC,
    DWARF_DISPLAY_ADVANCE_LOC,
  };

  struct Info {
    const char* name;
    uint8_t supported_version;
    uint8_t num_operands;
    uint8_t operands[2];
    uint8_t display_operands[2];
  };

  const static Info kTable[64];
};

template <typename AddressType>
class DwarfCfa {
  // Signed version of AddressType
  typedef typename std::make_signed<AddressType>::type SignedType;

 public:
  DwarfCfa(DwarfMemory* memory, const DwarfFDE* fde)
    : memory_(memory), fde_(fde) { }
  virtual ~DwarfCfa() = default;

  bool GetLocationInfo(uint64_t pc, uint64_t start_offset, uint64_t end_offset,
                       dwarf_loc_regs_t* loc_regs);

  bool Log(uint32_t indent, uint64_t pc, uint64_t load_bias, uint64_t start_offset,
           uint64_t end_offset);

  DwarfError last_error() { return last_error_; }

  AddressType cur_pc() { return cur_pc_; }

  void set_cie_loc_regs(const dwarf_loc_regs_t* cie_loc_regs) { cie_loc_regs_ = cie_loc_regs; }

 protected:
  std::string GetOperandString(uint8_t operand, uint64_t value, uint64_t* cur_pc);

  bool LogOffsetRegisterString(uint32_t indent, uint64_t cfa_offset, uint8_t reg);

  bool LogInstruction(uint32_t indent, uint64_t cfa_offset, uint8_t op, uint64_t* cur_pc);

 private:
  DwarfError last_error_;
  DwarfMemory* memory_;
  const DwarfFDE* fde_;

  AddressType cur_pc_;
  const dwarf_loc_regs_t* cie_loc_regs_ = nullptr;
  std::vector<AddressType> operands_;
  std::stack<dwarf_loc_regs_t> loc_reg_state_;

  // Static CFA processing functions.
  static bool cfa_nop(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_set_loc(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_advance_loc(DwarfCfa* ptr, dwarf_loc_regs_t*);
  static bool cfa_offset(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_restore(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_undefined(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_same_value(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_register(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_remember_state(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_restore_state(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_def_cfa(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_def_cfa_register(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_def_cfa_offset(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_def_cfa_expression(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_expression(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_offset_extended_sf(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_def_cfa_sf(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_def_cfa_offset_sf(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_val_offset(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_val_offset_sf(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_val_expression(DwarfCfa*, dwarf_loc_regs_t*);
  static bool cfa_gnu_negative_offset_extended(DwarfCfa*, dwarf_loc_regs_t*);

  constexpr static bool (*kCallbackTable[64])(DwarfCfa*, dwarf_loc_regs_t*) = {
    // 0x00 DW_CFA_nop
    cfa_nop,
    // 0x01 DW_CFA_set_loc
    cfa_set_loc,
    // 0x02 DW_CFA_advance_loc1
    cfa_advance_loc,
    // 0x03 DW_CFA_advance_loc2
    cfa_advance_loc,
    // 0x04 DW_CFA_advance_loc4
    cfa_advance_loc,
    // 0x05 DW_CFA_offset_extended
    cfa_offset,
    // 0x06 DW_CFA_restore_extended
    cfa_restore,
    // 0x07 DW_CFA_undefined
    cfa_undefined,
    // 0x08 DW_CFA_same_value
    cfa_same_value,
    // 0x09 DW_CFA_register
    cfa_register,
    // 0x0a DW_CFA_remember_state
    cfa_remember_state,
    // 0x0b DW_CFA_restore_state
    cfa_restore_state,
    // 0x0c DW_CFA_def_cfa
    cfa_def_cfa,
    // 0x0d DW_CFA_def_cfa_register
    cfa_def_cfa_register,
    // 0x0e DW_CFA_def_cfa_offset
    cfa_def_cfa_offset,
    // 0x0f DW_CFA_def_cfa_expression
    cfa_def_cfa_expression,
    // 0x10 DW_CFA_expression
    cfa_expression,
    // 0x11 DW_CFA_offset_extended_sf
    cfa_offset_extended_sf,
    // 0x12 DW_CFA_def_cfa_sf
    cfa_def_cfa_sf,
    // 0x13 DW_CFA_def_cfa_offset_sf
    cfa_def_cfa_offset_sf,
    // 0x14 DW_CFA_val_offset
    cfa_val_offset,
    // 0x15 DW_CFA_val_offset_sf
    cfa_val_offset_sf,
    // 0x16 DW_CFA_val_expression
    cfa_val_expression,
    // 0x17 illegal cfa
    nullptr,
    // 0x18 illegal cfa
    nullptr,
    // 0x19 illegal cfa
    nullptr,
    // 0x1a illegal cfa
    nullptr,
    // 0x1b illegal cfa
    nullptr,
    // 0x1c DW_CFA_lo_user (Treat this as illegal)
    nullptr,
    // 0x1d illegal cfa
    nullptr,
    // 0x1e illegal cfa
    nullptr,
    // 0x1f illegal cfa
    nullptr,
    // 0x20 illegal cfa
    nullptr,
    // 0x21 illegal cfa
    nullptr,
    // 0x22 illegal cfa
    nullptr,
    // 0x23 illegal cfa
    nullptr,
    // 0x24 illegal cfa
    nullptr,
    // 0x25 illegal cfa
    nullptr,
    // 0x26 illegal cfa
    nullptr,
    // 0x27 illegal cfa
    nullptr,
    // 0x28 illegal cfa
    nullptr,
    // 0x29 illegal cfa
    nullptr,
    // 0x2a illegal cfa
    nullptr,
    // 0x2b illegal cfa
    nullptr,
    // 0x2c illegal cfa
    nullptr,
    // 0x2d DW_CFA_GNU_window_save (Treat this as illegal)
    nullptr,
    // 0x2e DW_CFA_GNU_args_size
    cfa_nop,
    // 0x2f DW_CFA_GNU_negative_offset_extended
    cfa_gnu_negative_offset_extended,
    // 0x30 illegal cfa
    nullptr,
    // 0x31 illegal cfa
    nullptr,
    // 0x32 illegal cfa
    nullptr,
    // 0x33 illegal cfa
    nullptr,
    // 0x34 illegal cfa
    nullptr,
    // 0x35 illegal cfa
    nullptr,
    // 0x36 illegal cfa
    nullptr,
    // 0x37 illegal cfa
    nullptr,
    // 0x38 illegal cfa
    nullptr,
    // 0x39 illegal cfa
    nullptr,
    // 0x3a illegal cfa
    nullptr,
    // 0x3b illegal cfa
    nullptr,
    // 0x3c illegal cfa
    nullptr,
    // 0x3d illegal cfa
    nullptr,
    // 0x3e illegal cfa
    nullptr,
    // 0x3f DW_CFA_hi_user (Treat this as illegal)
    nullptr,
  };
};
template<typename AddressType> constexpr
    bool (*DwarfCfa<AddressType>::kCallbackTable[64])(DwarfCfa<AddressType>*, dwarf_loc_regs_t*);

#endif  // _LIBUNWINDSTACK_DWARF_CFA_H
