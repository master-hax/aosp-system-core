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

#ifndef _LIBANDROID_UNWIND_DWARF_UNWIND_H
#define _LIBANDROID_UNWIND_DWARF_UNWIND_H

#include "Memory.h"

enum DwarfOp : public uint16_t {
  DW_OP_addr,                 // 0x03, 1 operand of machine address size
  DW_OP_deref,                // 0x06, no operands
  DW_OP_const1u,              // 0x08, 1 operand of 1 byte
  DW_OP_const1s,              // 0x09, 1 operand of 1 byte
  DW_OP_const2u,              // 0x0a, 1 operand of 2 bytes
  DW_OP_const2s,              // 0x0b, 1 operand of 2 bytes
  DW_OP_const4u,              // 0x0c, 1 operand of 4 bytes
  DW_OP_const4s,              // 0x0d, 1 operand of 4 bytes
  DW_OP_const8u,              // 0x0e, 1 operand of 8 bytes
  DW_OP_const8s,              // 0x0f, 1 operand of 8 bytes
  DW_OP_constu,               // 0x10, 1 operand of ULEB128
  DW_OP_consts,               // 0x11, 1 operand of SLEB128
  DW_OP_dup,                  // 0x12, no operands
  DW_OP_drop,                 // 0x13, no operands
  DW_OP_over,                 // 0x14, no operands
  DW_OP_pick,                 // 0x15, 1 operand of 1 byte
  DW_OP_swap,                 // 0x16, no operands
  DW_OP_rot,                  // 0x17, no operands
  DW_OP_xderef,               // 0x18, no operands
  DW_OP_abs,                  // 0x19, no operands
  DW_OP_and,                  // 0x1a, no operands
  DW_OP_div,                  // 0x1b, no operands
  DW_OP_minus,                // 0x1c, no operands
  DW_OP_mod,                  // 0x1d, no operands
  DW_OP_mul,                  // 0x1e, no operands
  DW_OP_neg,                  // 0x1f, no operands
  DW_OP_not,                  // 0x20, no operands
  DW_OP_or,                   // 0x21, no operands
  DW_OP_plus,                 // 0x22, no operands
  DW_OP_plus_uconst,          // 0x23, 1 operand of ULEB128
  DW_OP_shl,                  // 0x24, no operands
  DW_OP_shr,                  // 0x25, no operands
  DW_OP_shra,                 // 0x26, no operands
  DW_OP_xor,                  // 0x27, no operands
  DW_OP_bra,                  // 0x28, 1 operand of 2 bytes
  DW_OP_eq,                   // 0x29, no operands
  DW_OP_ge,                   // 0x2a, no operands
  DW_OP_gt,                   // 0x2b, no operands
  DW_OP_le,                   // 0x2c, no operands
  DW_OP_lt,                   // 0x2d, no operands
  DW_OP_ne,                   // 0x2e, no operands
  DW_OP_skip,                 // 0x2f, 1 operand of 2 bytes
  DW_OP_lit0,                 // 0x30, no operands
  DW_OP_lit1,                 // 0x31, no operands
  DW_OP_lit2,                 // 0x32, no operands
  DW_OP_lit3,                 // 0x33, no operands
  DW_OP_lit4,                 // 0x34, no operands
  DW_OP_lit5,                 // 0x35, no operands
  DW_OP_lit6,                 // 0x36, no operands
  DW_OP_lit7,                 // 0x37, no operands
  DW_OP_lit8,                 // 0x38, no operands
  DW_OP_lit9,                 // 0x39, no operands
  DW_OP_lit10,                // 0x3a, no operands
  DW_OP_lit11,                // 0x3b, no operands
  DW_OP_lit12,                // 0x3c, no operands
  DW_OP_lit13,                // 0x3d, no operands
  DW_OP_lit14,                // 0x3e, no operands
  DW_OP_lit15,                // 0x3f, no operands
  DW_OP_lit16,                // 0x40, no operands
  DW_OP_lit17,                // 0x41, no operands
  DW_OP_lit18,                // 0x42, no operands
  DW_OP_lit19,                // 0x43, no operands
  DW_OP_lit20,                // 0x44, no operands
  DW_OP_lit21,                // 0x45, no operands
  DW_OP_lit22,                // 0x46, no operands
  DW_OP_lit23,                // 0x47, no operands
  DW_OP_lit24,                // 0x48, no operands
  DW_OP_lit25,                // 0x49, no operands
  DW_OP_lit26,                // 0x4a, no operands
  DW_OP_lit27,                // 0x4b, no operands
  DW_OP_lit28,                // 0x4c, no operands
  DW_OP_lit29,                // 0x4d, no operands
  DW_OP_lit30,                // 0x4e, no operands
  DW_OP_lit31,                // 0x4f, no operands
  DW_OP_reg0,                 // 0x50, no operands
  DW_OP_reg1,                 // 0x51, no operands
  DW_OP_reg2,                 // 0x52, no operands
  DW_OP_reg3,                 // 0x53, no operands
  DW_OP_reg4,                 // 0x54, no operands
  DW_OP_reg5,                 // 0x55, no operands
  DW_OP_reg6,                 // 0x56, no operands
  DW_OP_reg7,                 // 0x57, no operands
  DW_OP_reg8,                 // 0x58, no operands
  DW_OP_reg9,                 // 0x59, no operands
  DW_OP_reg10,                // 0x5a, no operands
  DW_OP_reg11,                // 0x5b, no operands
  DW_OP_reg12,                // 0x5c, no operands
  DW_OP_reg13,                // 0x5d, no operands
  DW_OP_reg14,                // 0x5e, no operands
  DW_OP_reg15,                // 0x5f, no operands
  DW_OP_reg16,                // 0x60, no operands
  DW_OP_reg17,                // 0x61, no operands
  DW_OP_reg18,                // 0x62, no operands
  DW_OP_reg19,                // 0x63, no operands
  DW_OP_reg20,                // 0x64, no operands
  DW_OP_reg21,                // 0x65, no operands
  DW_OP_reg22,                // 0x66, no operands
  DW_OP_reg23,                // 0x67, no operands
  DW_OP_reg24,                // 0x68, no operands
  DW_OP_reg25,                // 0x69, no operands
  DW_OP_reg26,                // 0x6a, no operands
  DW_OP_reg27,                // 0x6b, no operands
  DW_OP_reg28,                // 0x6c, no operands
  DW_OP_reg29,                // 0x6d, no operands
  DW_OP_reg30,                // 0x6e, no operands
  DW_OP_reg31,                // 0x6f, no operands
  DW_OP_breg0,                // 0x70, 1 operand of SLEB128
  DW_OP_breg1,                // 0x71, 1 operand of SLEB128
  DW_OP_breg2,                // 0x72, 1 operand of SLEB128
  DW_OP_breg3,                // 0x73, 1 operand of SLEB128
  DW_OP_breg4,                // 0x74, 1 operand of SLEB128
  DW_OP_breg5,                // 0x75, 1 operand of SLEB128
  DW_OP_breg6,                // 0x76, 1 operand of SLEB128
  DW_OP_breg7,                // 0x77, 1 operand of SLEB128
  DW_OP_breg8,                // 0x78, 1 operand of SLEB128
  DW_OP_breg9,                // 0x79, 1 operand of SLEB128
  DW_OP_breg10,               // 0x7a, 1 operand of SLEB128
  DW_OP_breg11,               // 0x7b, 1 operand of SLEB128
  DW_OP_breg12,               // 0x7c, 1 operand of SLEB128
  DW_OP_breg13,               // 0x7d, 1 operand of SLEB128
  DW_OP_breg14,               // 0x7e, 1 operand of SLEB128
  DW_OP_breg15,               // 0x7f, 1 operand of SLEB128
  DW_OP_breg16,               // 0x80, 1 operand of SLEB128
  DW_OP_breg17,               // 0x81, 1 operand of SLEB128
  DW_OP_breg18,               // 0x82, 1 operand of SLEB128
  DW_OP_breg19,               // 0x83, 1 operand of SLEB128
  DW_OP_breg20,               // 0x84, 1 operand of SLEB128
  DW_OP_breg21,               // 0x85, 1 operand of SLEB128
  DW_OP_breg22,               // 0x86, 1 operand of SLEB128
  DW_OP_breg23,               // 0x87, 1 operand of SLEB128
  DW_OP_breg24,               // 0x88, 1 operand of SLEB128
  DW_OP_breg25,               // 0x89, 1 operand of SLEB128
  DW_OP_breg26,               // 0x8a, 1 operand of SLEB128
  DW_OP_breg27,               // 0x8b, 1 operand of SLEB128
  DW_OP_breg28,               // 0x8c, 1 operand of SLEB128
  DW_OP_breg29,               // 0x8d, 1 operand of SLEB128
  DW_OP_breg30,               // 0x8e, 1 operand of SLEB128
  DW_OP_breg31,               // 0x8f, 1 operand of SLEB128
  DW_OP_regx,                 // 0x90, 1 operand of ULEB128
  DW_OP_fbreg,                // 0x91, 1 operand of SLEB128
  DW_OP_bregx,                // 0x92, 2 operands of ULEB128 then SLEB128
  DW_OP_piece,                // 0x93, 1 operand of ULEB128
  DW_OP_deref_size,           // 0x94, 1 operand of 1 byte
  DW_OP_xderef_size,          // 0x95, 1 operand of 1 byte
  DW_OP_nop,                  // 0x96, no operands
  DW_OP_push_object_address,  // 0x97, no operands (new in dwarf 3)
  DW_OP_call2,                // 0x98, 1 operand of 2 bytes (new in dwarf 3)
  DW_OP_call4,                // 0x99, 1 operand of 4 bytes (new in dwarf 3)
  DW_OP_call_ref,             // 0x9a, 1 operand of 4 bytes or 8 bytes (new in dwarf 3)
  DW_OP_form_tls_address,     // 0x9b, no operands (new in dwarf 3)
  DW_OP_call_frame_cfa,       // 0x9c, no operands (new in dwarf 3)
  DW_OP_bit_piece,            // 0x9d, 2 operands of ULEB128 then ULEB128 (new in dwarf 3)
  DW_OP_implicit_value,       // 0x9e, 2 operands of ULEB128 followed by block of that size (new in dwarf 4)
  DW_OP_stack_value,          // 0x9f, no operands (new in dwarf 4)
  DW_OP_lo_user,              // 0xe0
  DW_OP_hi_user,              // 0xff
};

class DwarfUnwind {
 public:
  DwarfUnwind(Memory* memory) : memory_(memory) { }
  virtual ~DwarfUnwind() = default;

  virtual bool Extract(uint64_t ip) = 0;

  virtual bool Decode() = 0;

 private:
};

class Dwarf1Unwind : public DwarfUnwind {
 public:
  Dwarf1Unwind(Memory* memory) : DwarfUnwind(memory) { }
  virtual ~Dwarf1Unwind() = default;

  bool Extract(uint64_t ip) override;

  bool Decode() override;

 private:
};

class Dwarf2Unwind : public DwarfUnwind {
 public:
  Dwarf2Unwind(Memory* memory) : DwarfUnwind(memory) { }
  virtual ~Dwarf2Unwind() = default;

  bool Extract(uint64_t ip) override;

  bool Decode() override;

 private:
};

class Dwarf3Unwind : public DwarfUnwind {
 public:
  Dwarf3Unwind(Memory* memory) : DwarfUnwind(memory) { }
  virtual ~Dwarf3Unwind() = default;

  bool Extract(uint64_t ip) override;

  bool Decode() override;

 private:
};

class Dwarf4Unwind : public DwarfUnwind {
 public:
  Dwarf4Unwind(Memory* memory) : DwarfUnwind(memory) { }
  virtual ~Dwarf4() = default;

  bool Extract(uint64_t ip) override;

  bool Decode() override;

 private:
};

#endif  // _LIBANDROID_UNWIND_DWARF_UNWIND_H
