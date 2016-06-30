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

#include <stdint.h>

#include "DwarfError.h"
#include "DwarfEncoding.h"
#include "DwarfOp.h"

static bool op_deref(DwarfOpBase*) {
  return true;
}

static bool op_push(DwarfOpBase* dwarf) {
  dwarf->InternalStackPushOperands();
  return true;
}

static bool op_dup(DwarfOpBase* dwarf) {
  uint64_t value;
  if (!dwarf->InternalStackAt(0, &value)) {
    return false;
  }

  dwarf->InternalStackPush(value);
  return true;
}

static bool op_drop(DwarfOpBase* dwarf) {
  dwarf->InternalStackPop();
  return true;
}

static bool op_over(DwarfOpBase* dwarf) {
  uint64_t value;
  if (!dwarf->InternalStackAt(1, &value)) {
    return false;
  }
  dwarf->InternalStackPush(value);
  return true;
}

static bool op_pick(DwarfOpBase* dwarf) {
  uint64_t index = dwarf->InternalOperandAt(0);
  uint64_t value;
  if (!dwarf->InternalStackAt(index, &value)) {
    return false;
  }
  dwarf->InternalStackPush(value);
  return true;
}

static bool op_swap(DwarfOpBase* dwarf) {
  return dwarf->InternalStackSwap();
}

static bool op_rot(DwarfOpBase*) {
  return true;
}

static bool op_xderef(DwarfOpBase*) {
  return true;
}

static bool op_abs(DwarfOpBase*) {
  return true;
}

static bool op_and(DwarfOpBase*) {
  return true;
}

static bool op_div(DwarfOpBase*) {
  return true;
}

static bool op_minus(DwarfOpBase*) {
  return true;
}

static bool op_mod(DwarfOpBase*) {
  return true;
}

static bool op_mul(DwarfOpBase*) {
  return true;
}

static bool op_neg(DwarfOpBase*) {
  return true;
}

static bool op_not(DwarfOpBase*) {
  return true;
}

static bool op_or(DwarfOpBase*) {
  return true;
}

static bool op_plus(DwarfOpBase*) {
  return true;
}

static bool op_plus_uconst(DwarfOpBase*) {
  return true;
}

static bool op_shl(DwarfOpBase*) {
  return true;
}

static bool op_shr(DwarfOpBase*) {
  return true;
}

static bool op_shra(DwarfOpBase*) {
  return true;
}

static bool op_xor(DwarfOpBase*) {
  return true;
}

static bool op_bra(DwarfOpBase*) {
  return true;
}

static bool op_eq(DwarfOpBase*) {
  return true;
}

static bool op_ge(DwarfOpBase*) {
  return true;
}

static bool op_gt(DwarfOpBase*) {
  return true;
}

static bool op_le(DwarfOpBase*) {
  return true;
}

static bool op_lt(DwarfOpBase*) {
  return true;
}

static bool op_ne(DwarfOpBase*) {
  return true;
}

static bool op_skip(DwarfOpBase*) {
  return true;
}

static bool op_lit(DwarfOpBase* dwarf) {
  dwarf->InternalStackPush(dwarf->cur_op() - 0x30);
  return true;
}

static bool op_reg(DwarfOpBase*) {
  return true;
}

static bool op_breg(DwarfOpBase*) {
  return true;
}

static bool op_regx(DwarfOpBase*) {
  return true;
}

static bool op_fbreg(DwarfOpBase*) {
  return true;
}

static bool op_bregx(DwarfOpBase*) {
  return true;
}

static bool op_piece(DwarfOpBase*) {
  return true;
}

static bool op_deref_size(DwarfOpBase*) {
  return true;
}

static bool op_xderef_size(DwarfOpBase*) {
  return true;
}

static bool op_push_object_address(DwarfOpBase*) {
  return true;
}

static bool op_call2(DwarfOpBase*) {
  return true;
}

static bool op_call4(DwarfOpBase*) {
  return true;
}

static bool op_call_ref(DwarfOpBase*) {
  return true;
}

static bool op_form_tls_address(DwarfOpBase*) {
  return true;
}

static bool op_call_frame_cfa(DwarfOpBase*) {
  return true;
}

static bool op_bit_piece(DwarfOpBase*) {
  return true;
}

static bool op_implicit_value(DwarfOpBase*) {
  return true;
}

static bool op_stack_value(DwarfOpBase*) {
  return true;
}

static bool op_nop(DwarfOpBase*) {
  return true;
}

DwarfOpCallback g_opcode_table[256] = {
  { nullptr, 0, 0, {} },      // 0x00 illegal op
  { nullptr, 0, 0, {} },      // 0x01 illegal op
  { nullptr, 0, 0, {} },      // 0x02 illegal op
  {                           // 0x03 DW_OP_addr
    op_push,
    2,
    1,
    { DW_EH_PE_absptr },
  },
  { nullptr, 0, 0, {} },      // 0x04 illegal op
  { nullptr, 0, 0, {} },      // 0x05 illegal op
  {                           // 0x06 DW_OP_deref
    op_deref,
    2,
    0,
    {},
  },
  { nullptr, 0, 0, {} },      // 0x07 illegal op
  {                           // 0x08 DW_OP_const1u
    op_push,
    2,
    1,
    { DW_EH_PE_udata1 },
  },
  {                           // 0x09 DW_OP_const1s
    op_push,
    2,
    1,
    { DW_EH_PE_sdata1 },
  },
  {                           // 0x0a DW_OP_const2u
    op_push,
    2,
    1,
    { DW_EH_PE_udata2 },
  },
  {                           // 0x0b DW_OP_const2s
    op_push,
    2,
    1,
    { DW_EH_PE_sdata2 },
  },
  {                           // 0x0c DW_OP_const4u
    op_push,
    2,
    1,
    { DW_EH_PE_udata4 },
  },
  {                           // 0x0d DW_OP_const4s
    op_push,
    2,
    1,
    { DW_EH_PE_sdata4 },
  },
  {                           // 0x0e DW_OP_const8u
    op_push,
    2,
    1,
    { DW_EH_PE_udata8 },
  },
  {                           // 0x0f DW_OP_const8s
    op_push,
    2,
    1,
    { DW_EH_PE_sdata8 },
  },
  {                           // 0x10 DW_OP_constu
    op_push,
    2,
    1,
    { DW_EH_PE_uleb128 },
  },
  {                           // 0x11 DW_OP_consts
    op_push,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x12 DW_OP_dup
    op_dup,
    2,
    0,
    {},
  },
  {                           // 0x13 DW_OP_drop
    op_drop,
    2,
    0,
    {},
  },
  {                           // 0x14 DW_OP_over
    op_over,
    2,
    0,
    {},
  },
  {                           // 0x15 DW_OP_pick
    op_pick,
    2,
    1,
    { DW_EH_PE_udata1 },
  },
  {                           // 0x16 DW_OP_swap
    op_swap,
    2,
    0,
    {},
  },
  {                           // 0x17 DW_OP_rot
    op_rot,
    2,
    0,
    {},
  },
  {                           // 0x18 DW_OP_xderef
    op_xderef,
    2,
    0,
    {},
  },
  {                           // 0x19 DW_OP_abs
    op_abs,
    2,
    0,
    {},
  },
  {                           // 0x1a DW_OP_and
    op_and,
    2,
    0,
    {},
  },
  {                           // 0x1b DW_OP_div
    op_div,
    2,
    0,
    {},
  },
  {                           // 0x1c DW_OP_minus
    op_minus,
    2,
    0,
    {},
  },
  {                           // 0x1d DW_OP_mod
    op_mod,
    2,
    0,
    {},
  },
  {                           // 0x1e DW_OP_mul
    op_mul,
    2,
    0,
    {},
  },
  {                           // 0x1f DW_OP_neg
    op_neg,
    2,
    0,
    {},
  },
  {                           // 0x20 DW_OP_not
    op_not,
    2,
    0,
    {},
  },
  {                           // 0x21 DW_OP_or
    op_or,
    2,
    0,
    {},
  },
  {                           // 0x22 DW_OP_plus
    op_plus,
    2,
    0,
    {},
  },
  {                           // 0x23 DW_OP_plus_uconst
    op_plus_uconst,
    2,
    1,
    { DW_EH_PE_uleb128 },
  },
  {                           // 0x24 DW_OP_shl
    op_shl,
    2,
    0,
    {},
  },
  {                           // 0x25 DW_OP_shr
    op_shr,
    2,
    0,
    {},
  },
  {                           // 0x26 DW_OP_shra
    op_shra,
    2,
    0,
    {},
  },
  {                           // 0x27 DW_OP_xor
    op_xor,
    2,
    0,
    {},
  },
  {                           // 0x28 DW_OP_bra
    op_bra,
    2,
    1,
    { DW_EH_PE_sdata2 },
  },
  {                           // 0x29 DW_OP_eq
    op_eq,
    2,
    0,
    {},
  },
  {                           // 0x2a DW_OP_ge
    op_ge,
    2,
    0,
    {},
  },
  {                           // 0x2b DW_OP_gt
    op_gt,
    2,
    0,
    {},
  },
  {                           // 0x2c DW_OP_le
    op_le,
    2,
    0,
    {},
  },
  {                           // 0x2d DW_OP_lt
    op_lt,
    2,
    0,
    {},
  },
  {                           // 0x2e DW_OP_ne
    op_ne,
    2,
    0,
    {},
  },
  {                           // 0x2f DW_OP_skip
    op_skip,
    2,
    1,
    { DW_EH_PE_sdata2 },
  },
  {                           // 0x30 DW_OP_lit0
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x31 DW_OP_lit1
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x32 DW_OP_lit2
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x33 DW_OP_lit3
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x34 DW_OP_lit4
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x35 DW_OP_lit5
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x36 DW_OP_lit6
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x37 DW_OP_lit7
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x38 DW_OP_lit8
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x39 DW_OP_lit9
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x3a DW_OP_lit10
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x3b DW_OP_lit11
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x3c DW_OP_lit12
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x3d DW_OP_lit13
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x3e DW_OP_lit14
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x3f DW_OP_lit15
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x40 DW_OP_lit16
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x41 DW_OP_lit17
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x42 DW_OP_lit18
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x43 DW_OP_lit19
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x44 DW_OP_lit20
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x45 DW_OP_lit21
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x46 DW_OP_lit22
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x47 DW_OP_lit23
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x48 DW_OP_lit24
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x49 DW_OP_lit25
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x4a DW_OP_lit26
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x4b DW_OP_lit27
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x4c DW_OP_lit28
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x4d DW_OP_lit29
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x4e DW_OP_lit30
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x4f DW_OP_lit31
    op_lit,
    2,
    0,
    {},
  },
  {                           // 0x50 DW_OP_reg0
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x51 DW_OP_reg1
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x52 DW_OP_reg2
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x53 DW_OP_reg3
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x54 DW_OP_reg4
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x55 DW_OP_reg5
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x56 DW_OP_reg6
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x57 DW_OP_reg7
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x58 DW_OP_reg8
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x59 DW_OP_reg9
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x5a DW_OP_reg10
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x5b DW_OP_reg11
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x5c DW_OP_reg12
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x5d DW_OP_reg13
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x5e DW_OP_reg14
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x5f DW_OP_reg15
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x60 DW_OP_reg16
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x61 DW_OP_reg17
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x62 DW_OP_reg18
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x63 DW_OP_reg19
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x64 DW_OP_reg20
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x65 DW_OP_reg21
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x66 DW_OP_reg22
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x67 DW_OP_reg23
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x68 DW_OP_reg24
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x69 DW_OP_reg25
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x6a DW_OP_reg26
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x6b DW_OP_reg27
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x6c DW_OP_reg28
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x6d DW_OP_reg29
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x6e DW_OP_reg30
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x6f DW_OP_reg31
    op_reg,
    2,
    0,
    {},
  },
  {                           // 0x70 DW_OP_breg0
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x71 DW_OP_breg1
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x72 DW_OP_breg2
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x73 DW_OP_breg3
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x74 DW_OP_breg4
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x75 DW_OP_breg5
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x76 DW_OP_breg6
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x77 DW_OP_breg7
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x78 DW_OP_breg8
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x79 DW_OP_breg9
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x7a DW_OP_breg10
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x7b DW_OP_breg11
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x7c DW_OP_breg12
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x7d DW_OP_breg13
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x7e DW_OP_breg14
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x7f DW_OP_breg15
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x80 DW_OP_breg16
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x81 DW_OP_breg17
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x82 DW_OP_breg18
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x83 DW_OP_breg19
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x84 DW_OP_breg20
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x85 DW_OP_breg21
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x86 DW_OP_breg22
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x87 DW_OP_breg23
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x88 DW_OP_breg24
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x89 DW_OP_breg25
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x8a DW_OP_breg26
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x8b DW_OP_breg27
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x8c DW_OP_breg28
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x8d DW_OP_breg29
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x8e DW_OP_breg30
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x8f DW_OP_breg31
    op_breg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x90 DW_OP_regx
    op_regx,
    2,
    1,
    { DW_EH_PE_uleb128 },
  },
  {                           // 0x91 DW_OP_fbreg
    op_fbreg,
    2,
    1,
    { DW_EH_PE_sleb128 },
  },
  {                           // 0x92 DW_OP_bregx
    op_bregx,
    2,
    2,
    { DW_EH_PE_uleb128, DW_EH_PE_sleb128 },
  },
  {                           // 0x93 DW_OP_piece
    op_piece,
    2,
    1,
    { DW_EH_PE_uleb128 },
  },
  {                           // 0x94 DW_OP_deref_size
    op_deref_size,
    2,
    1,
    { DW_EH_PE_udata1 },
  },
  {                           // 0x95 DW_OP_xderef_size
    op_xderef_size,
    2,
    1,
    { DW_EH_PE_udata1 },
  },
  {                           // 0x96 DW_OP_nop
    op_nop,
    2,
    0,
    {},
  },
  {                           // 0x97 DW_OP_push_object_address
    op_push_object_address,
    3,
    0,
    {},
  },
  {                           // 0x98 DW_OP_call2
    op_call2,
    3,
    1,
    { DW_EH_PE_udata2 },
  },
  {                           // 0x99 DW_OP_call4
    op_call4,
    3,
    1,
    { DW_EH_PE_udata4 },
  },
  {                           // 0x9a DW_OP_call_ref
    op_call_ref,
    3,
    0, // Has a different sized operand (4 bytes or 8 bytes).
    {},
  },
  {                           // 0x9b DW_OP_form_tls_address
    op_form_tls_address,
    3,
    0,
    {},
  },
  {                           // 0x9c DW_OP_call_frame_cfa
    op_call_frame_cfa,
    3,
    0,
    {},
  },
  {                           // 0x9d DW_OP_bit_piece
    op_bit_piece,
    3,
    1,
    { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
  },
  {                           // 0x9e DW_OP_implicit_value
    op_implicit_value,
    4,
    1,
    { DW_EH_PE_uleb128 },
  },
  {                           // 0x9f DW_OP_stack_value
    op_stack_value,
    4,
    0,
    {},
  },
  { nullptr, 0, 0, {} },      // 0xa0 illegal op
  { nullptr, 0, 0, {} },      // 0xa1 illegal op
  { nullptr, 0, 0, {} },      // 0xa2 illegal op
  { nullptr, 0, 0, {} },      // 0xa3 illegal op
  { nullptr, 0, 0, {} },      // 0xa4 illegal op
  { nullptr, 0, 0, {} },      // 0xa5 illegal op
  { nullptr, 0, 0, {} },      // 0xa6 illegal op
  { nullptr, 0, 0, {} },      // 0xa7 illegal op
  { nullptr, 0, 0, {} },      // 0xa8 illegal op
  { nullptr, 0, 0, {} },      // 0xa9 illegal op
  { nullptr, 0, 0, {} },      // 0xaa illegal op
  { nullptr, 0, 0, {} },      // 0xab illegal op
  { nullptr, 0, 0, {} },      // 0xac illegal op
  { nullptr, 0, 0, {} },      // 0xad illegal op
  { nullptr, 0, 0, {} },      // 0xae illegal op
  { nullptr, 0, 0, {} },      // 0xaf illegal op
  { nullptr, 0, 0, {} },      // 0xb0 illegal op
  { nullptr, 0, 0, {} },      // 0xb1 illegal op
  { nullptr, 0, 0, {} },      // 0xb2 illegal op
  { nullptr, 0, 0, {} },      // 0xb3 illegal op
  { nullptr, 0, 0, {} },      // 0xb4 illegal op
  { nullptr, 0, 0, {} },      // 0xb5 illegal op
  { nullptr, 0, 0, {} },      // 0xb6 illegal op
  { nullptr, 0, 0, {} },      // 0xb7 illegal op
  { nullptr, 0, 0, {} },      // 0xb8 illegal op
  { nullptr, 0, 0, {} },      // 0xb9 illegal op
  { nullptr, 0, 0, {} },      // 0xba illegal op
  { nullptr, 0, 0, {} },      // 0xbb illegal op
  { nullptr, 0, 0, {} },      // 0xbc illegal op
  { nullptr, 0, 0, {} },      // 0xbd illegal op
  { nullptr, 0, 0, {} },      // 0xbe illegal op
  { nullptr, 0, 0, {} },      // 0xbf illegal op
  { nullptr, 0, 0, {} },      // 0xc0 illegal op
  { nullptr, 0, 0, {} },      // 0xc1 illegal op
  { nullptr, 0, 0, {} },      // 0xc2 illegal op
  { nullptr, 0, 0, {} },      // 0xc3 illegal op
  { nullptr, 0, 0, {} },      // 0xc4 illegal op
  { nullptr, 0, 0, {} },      // 0xc5 illegal op
  { nullptr, 0, 0, {} },      // 0xc6 illegal op
  { nullptr, 0, 0, {} },      // 0xc7 illegal op
  { nullptr, 0, 0, {} },      // 0xc8 illegal op
  { nullptr, 0, 0, {} },      // 0xc9 illegal op
  { nullptr, 0, 0, {} },      // 0xca illegal op
  { nullptr, 0, 0, {} },      // 0xcb illegal op
  { nullptr, 0, 0, {} },      // 0xcc illegal op
  { nullptr, 0, 0, {} },      // 0xcd illegal op
  { nullptr, 0, 0, {} },      // 0xce illegal op
  { nullptr, 0, 0, {} },      // 0xcf illegal op
  { nullptr, 0, 0, {} },      // 0xd0 illegal op
  { nullptr, 0, 0, {} },      // 0xd1 illegal op
  { nullptr, 0, 0, {} },      // 0xd2 illegal op
  { nullptr, 0, 0, {} },      // 0xd3 illegal op
  { nullptr, 0, 0, {} },      // 0xd4 illegal op
  { nullptr, 0, 0, {} },      // 0xd5 illegal op
  { nullptr, 0, 0, {} },      // 0xd6 illegal op
  { nullptr, 0, 0, {} },      // 0xd7 illegal op
  { nullptr, 0, 0, {} },      // 0xd8 illegal op
  { nullptr, 0, 0, {} },      // 0xd9 illegal op
  { nullptr, 0, 0, {} },      // 0xda illegal op
  { nullptr, 0, 0, {} },      // 0xdb illegal op
  { nullptr, 0, 0, {} },      // 0xdc illegal op
  { nullptr, 0, 0, {} },      // 0xdd illegal op
  { nullptr, 0, 0, {} },      // 0xde illegal op
  { nullptr, 0, 0, {} },      // 0xdf illegal op
  { nullptr, 0, 0, {} },      // 0xe0 DW_OP_lo_user
  { nullptr, 0, 0, {} },      // 0xe1 illegal op
  { nullptr, 0, 0, {} },      // 0xe2 illegal op
  { nullptr, 0, 0, {} },      // 0xe3 illegal op
  { nullptr, 0, 0, {} },      // 0xe4 illegal op
  { nullptr, 0, 0, {} },      // 0xe5 illegal op
  { nullptr, 0, 0, {} },      // 0xe6 illegal op
  { nullptr, 0, 0, {} },      // 0xe7 illegal op
  { nullptr, 0, 0, {} },      // 0xe8 illegal op
  { nullptr, 0, 0, {} },      // 0xe9 illegal op
  { nullptr, 0, 0, {} },      // 0xea illegal op
  { nullptr, 0, 0, {} },      // 0xeb illegal op
  { nullptr, 0, 0, {} },      // 0xec illegal op
  { nullptr, 0, 0, {} },      // 0xed illegal op
  { nullptr, 0, 0, {} },      // 0xee illegal op
  { nullptr, 0, 0, {} },      // 0xef illegal op
  { nullptr, 0, 0, {} },      // 0xf0 illegal op
  { nullptr, 0, 0, {} },      // 0xf1 illegal op
  { nullptr, 0, 0, {} },      // 0xf2 illegal op
  { nullptr, 0, 0, {} },      // 0xf3 illegal op
  { nullptr, 0, 0, {} },      // 0xf4 illegal op
  { nullptr, 0, 0, {} },      // 0xf5 illegal op
  { nullptr, 0, 0, {} },      // 0xf6 illegal op
  { nullptr, 0, 0, {} },      // 0xf7 illegal op
  { nullptr, 0, 0, {} },      // 0xf8 illegal op
  { nullptr, 0, 0, {} },      // 0xf9 illegal op
  { nullptr, 0, 0, {} },      // 0xfa illegal op
  { nullptr, 0, 0, {} },      // 0xfb illegal op
  { nullptr, 0, 0, {} },      // 0xfc illegal op
  { nullptr, 0, 0, {} },      // 0xfd illegal op
  { nullptr, 0, 0, {} },      // 0xfe illegal op
  { nullptr, 0, 0, {} },      // 0xff DW_OP_hi_user
};

const char* g_opcode_names[256] = {
  nullptr,                      // 0x00 illegal op
  nullptr,                      // 0x01 illegal op
  nullptr,                      // 0x02 illegal op
  "DW_OP_addr",                 // 0x03 DW_OP_addr
  nullptr,                      // 0x04 illegal op
  nullptr,                      // 0x05 illegal op
  "DW_OP_deref",                // 0x06 DW_OP_deref
  nullptr,                      // 0x07 illegal op
  "DW_OP_const1u",              // 0x08 DW_OP_const1u
  "DW_OP_const1s",              // 0x09 DW_OP_const1s
  "DW_OP_const2u",              // 0x0a DW_OP_const2u
  "DW_OP_const2s",              // 0x0b DW_OP_const2s
  "DW_OP_const4u",              // 0x0c DW_OP_const4u
  "DW_OP_const4s",              // 0x0d DW_OP_const4s
  "DW_OP_const8u",              // 0x0e DW_OP_const8u
  "DW_OP_const8s",              // 0x0f DW_OP_const8s
  "DW_OP_constu",               // 0x10 DW_OP_constu
  "DW_OP_consts",               // 0x11 DW_OP_consts
  "DW_OP_dup",                  // 0x12 DW_OP_dup
  "DW_OP_drop",                 // 0x13 DW_OP_drop
  "DW_OP_over",                 // 0x14 DW_OP_over
  "DW_OP_pick",                 // 0x15 DW_OP_pick
  "DW_OP_swap",                 // 0x16 DW_OP_swap
  "DW_OP_rot",                  // 0x17 DW_OP_rot
  "DW_OP_xderef",               // 0x18 DW_OP_xderef
  "DW_OP_abs",                  // 0x19 DW_OP_abs
  "DW_OP_and",                  // 0x1a DW_OP_and
  "DW_OP_div",                  // 0x1b DW_OP_div
  "DW_OP_minus",                // 0x1c DW_OP_minus
  "DW_OP_mod",                  // 0x1d DW_OP_mod
  "DW_OP_mul",                  // 0x1e DW_OP_mul
  "DW_OP_neg",                  // 0x1f DW_OP_neg
  "DW_OP_not",                  // 0x20 DW_OP_not
  "DW_OP_or",                   // 0x21 DW_OP_or
  "DW_OP_plus",                 // 0x22 DW_OP_plus
  "DW_OP_plus_uconst",          // 0x23 DW_OP_plus_uconst
  "DW_OP_shl",                  // 0x24 DW_OP_shl
  "DW_OP_shr",                  // 0x25 DW_OP_shr
  "DW_OP_shra",                 // 0x26 DW_OP_shra
  "DW_OP_xor",                  // 0x27 DW_OP_xor
  "DW_OP_bra",                  // 0x28 DW_OP_bra
  "DW_OP_eq",                   // 0x29 DW_OP_eq
  "DW_OP_ge",                   // 0x2a DW_OP_ge
  "DW_OP_gt",                   // 0x2b DW_OP_gt
  "DW_OP_le",                   // 0x2c DW_OP_le
  "DW_OP_lt",                   // 0x2d DW_OP_lt
  "DW_OP_ne",                   // 0x2e DW_OP_ne
  "DW_OP_skip",                 // 0x2f DW_OP_skip
  "DW_OP_lit0",                 // 0x30 DW_OP_lit0
  "DW_OP_lit1",                 // 0x31 DW_OP_lit1
  "DW_OP_lit2",                 // 0x32 DW_OP_lit2
  "DW_OP_lit3",                 // 0x33 DW_OP_lit3
  "DW_OP_lit4",                 // 0x34 DW_OP_lit4
  "DW_OP_lit5",                 // 0x35 DW_OP_lit5
  "DW_OP_lit6",                 // 0x36 DW_OP_lit6
  "DW_OP_lit7",                 // 0x37 DW_OP_lit7
  "DW_OP_lit8",                 // 0x38 DW_OP_lit8
  "DW_OP_lit9",                 // 0x39 DW_OP_lit9
  "DW_OP_lit10",                // 0x3a DW_OP_lit10
  "DW_OP_lit11",                // 0x3b DW_OP_lit11
  "DW_OP_lit12",                // 0x3c DW_OP_lit12
  "DW_OP_lit13",                // 0x3d DW_OP_lit13
  "DW_OP_lit14",                // 0x3e DW_OP_lit14
  "DW_OP_lit15",                // 0x3f DW_OP_lit15
  "DW_OP_lit16",                // 0x40 DW_OP_lit16
  "DW_OP_lit17",                // 0x41 DW_OP_lit17
  "DW_OP_lit18",                // 0x42 DW_OP_lit18
  "DW_OP_lit19",                // 0x43 DW_OP_lit19
  "DW_OP_lit20",                // 0x44 DW_OP_lit20
  "DW_OP_lit21",                // 0x45 DW_OP_lit21
  "DW_OP_lit22",                // 0x46 DW_OP_lit22
  "DW_OP_lit23",                // 0x47 DW_OP_lit23
  "DW_OP_lit24",                // 0x48 DW_OP_lit24
  "DW_OP_lit25",                // 0x49 DW_OP_lit25
  "DW_OP_lit26",                // 0x4a DW_OP_lit26
  "DW_OP_lit27",                // 0x4b DW_OP_lit27
  "DW_OP_lit28",                // 0x4c DW_OP_lit28
  "DW_OP_lit29",                // 0x4d DW_OP_lit29
  "DW_OP_lit30",                // 0x4e DW_OP_lit30
  "DW_OP_lit31",                // 0x4f DW_OP_lit31
  "DW_OP_reg0",                 // 0x50 DW_OP_reg0
  "DW_OP_reg1",                 // 0x51 DW_OP_reg1
  "DW_OP_reg2",                 // 0x52 DW_OP_reg2
  "DW_OP_reg3",                 // 0x53 DW_OP_reg3
  "DW_OP_reg4",                 // 0x54 DW_OP_reg4
  "DW_OP_reg5",                 // 0x55 DW_OP_reg5
  "DW_OP_reg6",                 // 0x56 DW_OP_reg6
  "DW_OP_reg7",                 // 0x57 DW_OP_reg7
  "DW_OP_reg8",                 // 0x58 DW_OP_reg8
  "DW_OP_reg9",                 // 0x59 DW_OP_reg9
  "DW_OP_reg10",                // 0x5a DW_OP_reg10
  "DW_OP_reg11",                // 0x5b DW_OP_reg11
  "DW_OP_reg12",                // 0x5c DW_OP_reg12
  "DW_OP_reg13",                // 0x5d DW_OP_reg13
  "DW_OP_reg14",                // 0x5e DW_OP_reg14
  "DW_OP_reg15",                // 0x5f DW_OP_reg15
  "DW_OP_reg16",                // 0x60 DW_OP_reg16
  "DW_OP_reg17",                // 0x61 DW_OP_reg17
  "DW_OP_reg18",                // 0x62 DW_OP_reg18
  "DW_OP_reg19",                // 0x63 DW_OP_reg19
  "DW_OP_reg20",                // 0x64 DW_OP_reg20
  "DW_OP_reg21",                // 0x65 DW_OP_reg21
  "DW_OP_reg22",                // 0x66 DW_OP_reg22
  "DW_OP_reg23",                // 0x67 DW_OP_reg23
  "DW_OP_reg24",                // 0x68 DW_OP_reg24
  "DW_OP_reg25",                // 0x69 DW_OP_reg25
  "DW_OP_reg26",                // 0x6a DW_OP_reg26
  "DW_OP_reg27",                // 0x6b DW_OP_reg27
  "DW_OP_reg28",                // 0x6c DW_OP_reg28
  "DW_OP_reg29",                // 0x6d DW_OP_reg29
  "DW_OP_reg30",                // 0x6e DW_OP_reg30
  "DW_OP_reg31",                // 0x6f DW_OP_reg31
  "DW_OP_breg0",                // 0x70 DW_OP_breg0
  "DW_OP_breg1",                // 0x71 DW_OP_breg1
  "DW_OP_breg2",                // 0x72 DW_OP_breg2
  "DW_OP_breg3",                // 0x73 DW_OP_breg3
  "DW_OP_breg4",                // 0x74 DW_OP_breg4
  "DW_OP_breg5",                // 0x75 DW_OP_breg5
  "DW_OP_breg6",                // 0x76 DW_OP_breg6
  "DW_OP_breg7",                // 0x77 DW_OP_breg7
  "DW_OP_breg8",                // 0x78 DW_OP_breg8
  "DW_OP_breg9",                // 0x79 DW_OP_breg9
  "DW_OP_breg10",               // 0x7a DW_OP_breg10
  "DW_OP_breg11",               // 0x7b DW_OP_breg11
  "DW_OP_breg12",               // 0x7c DW_OP_breg12
  "DW_OP_breg13",               // 0x7d DW_OP_breg13
  "DW_OP_breg14",               // 0x7e DW_OP_breg14
  "DW_OP_breg15",               // 0x7f DW_OP_breg15
  "DW_OP_breg16",               // 0x80 DW_OP_breg16
  "DW_OP_breg17",               // 0x81 DW_OP_breg17
  "DW_OP_breg18",               // 0x82 DW_OP_breg18
  "DW_OP_breg19",               // 0x83 DW_OP_breg19
  "DW_OP_breg20",               // 0x84 DW_OP_breg20
  "DW_OP_breg21",               // 0x85 DW_OP_breg21
  "DW_OP_breg22",               // 0x86 DW_OP_breg22
  "DW_OP_breg23",               // 0x87 DW_OP_breg23
  "DW_OP_breg24",               // 0x88 DW_OP_breg24
  "DW_OP_breg25",               // 0x89 DW_OP_breg25
  "DW_OP_breg26",               // 0x8a DW_OP_breg26
  "DW_OP_breg27",               // 0x8b DW_OP_breg27
  "DW_OP_breg28",               // 0x8c DW_OP_breg28
  "DW_OP_breg29",               // 0x8d DW_OP_breg29
  "DW_OP_breg30",               // 0x8e DW_OP_breg30
  "DW_OP_breg31",               // 0x8f DW_OP_breg31
  "DW_OP_regx",                 // 0x90 DW_OP_regx
  "DW_OP_fbreg",                // 0x91 DW_OP_fbreg
  "DW_OP_bregx",                // 0x92 DW_OP_bregx
  "DW_OP_piece",                // 0x93 DW_OP_piece
  "DW_OP_deref_size",           // 0x94 DW_OP_deref_size
  "DW_OP_xderef_size",          // 0x95 DW_OP_xderef_size
  "DW_OP_nop",                  // 0x96 DW_OP_nop
  "DW_OP_push_object_address",  // 0x97 DW_OP_push_object_address
  "DW_OP_call2",                // 0x98 DW_OP_call2
  "DW_OP_call4",                // 0x99 DW_OP_call4
  "DW_OP_call_ref",             // 0x9a DW_OP_call_ref
  "DW_OP_form_tls_address",     // 0x9b DW_OP_form_tls_address
  "DW_OP_call_frame_cfa",       // 0x9c DW_OP_call_frame_cfa
  "DW_OP_bit_piece",            // 0x9d DW_OP_bit_piece
  "DW_OP_implicit_value",       // 0x9e DW_OP_implicit_value
  "DW_OP_stack_value",          // 0x9f DW_OP_stack_value
  nullptr,                      // 0xa0 illegal op
  nullptr,                      // 0xa1 illegal op
  nullptr,                      // 0xa2 illegal op
  nullptr,                      // 0xa3 illegal op
  nullptr,                      // 0xa4 illegal op
  nullptr,                      // 0xa5 illegal op
  nullptr,                      // 0xa6 illegal op
  nullptr,                      // 0xa7 illegal op
  nullptr,                      // 0xa8 illegal op
  nullptr,                      // 0xa9 illegal op
  nullptr,                      // 0xaa illegal op
  nullptr,                      // 0xab illegal op
  nullptr,                      // 0xac illegal op
  nullptr,                      // 0xad illegal op
  nullptr,                      // 0xae illegal op
  nullptr,                      // 0xaf illegal op
  nullptr,                      // 0xb0 illegal op
  nullptr,                      // 0xb1 illegal op
  nullptr,                      // 0xb2 illegal op
  nullptr,                      // 0xb3 illegal op
  nullptr,                      // 0xb4 illegal op
  nullptr,                      // 0xb5 illegal op
  nullptr,                      // 0xb6 illegal op
  nullptr,                      // 0xb7 illegal op
  nullptr,                      // 0xb8 illegal op
  nullptr,                      // 0xb9 illegal op
  nullptr,                      // 0xba illegal op
  nullptr,                      // 0xbb illegal op
  nullptr,                      // 0xbc illegal op
  nullptr,                      // 0xbd illegal op
  nullptr,                      // 0xbe illegal op
  nullptr,                      // 0xbf illegal op
  nullptr,                      // 0xc0 illegal op
  nullptr,                      // 0xc1 illegal op
  nullptr,                      // 0xc2 illegal op
  nullptr,                      // 0xc3 illegal op
  nullptr,                      // 0xc4 illegal op
  nullptr,                      // 0xc5 illegal op
  nullptr,                      // 0xc6 illegal op
  nullptr,                      // 0xc7 illegal op
  nullptr,                      // 0xc8 illegal op
  nullptr,                      // 0xc9 illegal op
  nullptr,                      // 0xca illegal op
  nullptr,                      // 0xcb illegal op
  nullptr,                      // 0xcc illegal op
  nullptr,                      // 0xcd illegal op
  nullptr,                      // 0xce illegal op
  nullptr,                      // 0xcf illegal op
  nullptr,                      // 0xd0 illegal op
  nullptr,                      // 0xd1 illegal op
  nullptr,                      // 0xd2 illegal op
  nullptr,                      // 0xd3 illegal op
  nullptr,                      // 0xd4 illegal op
  nullptr,                      // 0xd5 illegal op
  nullptr,                      // 0xd6 illegal op
  nullptr,                      // 0xd7 illegal op
  nullptr,                      // 0xd8 illegal op
  nullptr,                      // 0xd9 illegal op
  nullptr,                      // 0xda illegal op
  nullptr,                      // 0xdb illegal op
  nullptr,                      // 0xdc illegal op
  nullptr,                      // 0xdd illegal op
  nullptr,                      // 0xde illegal op
  nullptr,                      // 0xdf illegal op
  "DW_OP_lo_user",              // 0xe0 DW_OP_lo_user
  nullptr,                      // 0xe1 illegal op
  nullptr,                      // 0xe2 illegal op
  nullptr,                      // 0xe3 illegal op
  nullptr,                      // 0xe4 illegal op
  nullptr,                      // 0xe5 illegal op
  nullptr,                      // 0xe6 illegal op
  nullptr,                      // 0xe7 illegal op
  nullptr,                      // 0xe8 illegal op
  nullptr,                      // 0xe9 illegal op
  nullptr,                      // 0xea illegal op
  nullptr,                      // 0xeb illegal op
  nullptr,                      // 0xec illegal op
  nullptr,                      // 0xed illegal op
  nullptr,                      // 0xee illegal op
  nullptr,                      // 0xef illegal op
  nullptr,                      // 0xf0 illegal op
  nullptr,                      // 0xf1 illegal op
  nullptr,                      // 0xf2 illegal op
  nullptr,                      // 0xf3 illegal op
  nullptr,                      // 0xf4 illegal op
  nullptr,                      // 0xf5 illegal op
  nullptr,                      // 0xf6 illegal op
  nullptr,                      // 0xf7 illegal op
  nullptr,                      // 0xf8 illegal op
  nullptr,                      // 0xf9 illegal op
  nullptr,                      // 0xfa illegal op
  nullptr,                      // 0xfb illegal op
  nullptr,                      // 0xfc illegal op
  nullptr,                      // 0xfd illegal op
  nullptr,                      // 0xfe illegal op
  "DW_OP_hi_user",              // 0xff DW_OP_hi_user
};
