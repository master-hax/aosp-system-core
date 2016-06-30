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

#ifndef _LIBANDROID_UNWIND_DWARF_OP_H
#define _LIBANDROID_UNWIND_DWARF_OP_H

#include <stdint.h>

#include <vector>
#include <deque>

#include "DwarfMemory.h"
#include "DwarfError.h"
#include "Memory.h"

struct DwarfOpCallback {
  bool (*handle_func)(void*);
  uint8_t supported_version;
  uint8_t num_operands;
  uint8_t operands[2];
};

class DwarfOpBase {
 public:
  DwarfOpBase(Memory* regular_memory) : regular_memory_(regular_memory) { }
  virtual ~DwarfOpBase() = default;

  DwarfError last_error() { return last_error_; }
  uint8_t cur_op() { return cur_op_; }

  virtual bool Eval(uint8_t) = 0;

 protected:
  Memory* regular_memory_;
  DwarfError last_error_;
  uint8_t cur_op_;
};

template <typename AddressType>
class DwarfOp : public DwarfOpBase {
 public:
  DwarfOp(DwarfMemory<AddressType>* memory, Memory* regular_memory)
    : DwarfOpBase(regular_memory), memory_(memory) { }
  virtual ~DwarfOp() = default;

  bool Eval(uint8_t version) override {
    last_error_ = DWARF_ERROR_NONE;
    if (!memory_->ReadBytes(&cur_op_, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }

    const DwarfOpCallback* op = &kCallbackTable[cur_op_];
    if (op->handle_func == nullptr) {
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    // Check for an unsupported opcode.
    if (version < op->supported_version) {
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    operands_.clear();
    for (size_t i = 0; i < op->num_operands; i++) {
      if (!GetOperand(op->operands[i])) {
        return false;
      }
    }
    return op->handle_func(this);
  }

  AddressType OperandAt(size_t index) { return operands_[index]; }

  void StackPush(AddressType value) { stack_.push_front(value); }
  AddressType StackPop() {
    AddressType value = stack_.front();
    stack_.pop_front();
    return value;
  }

  bool StackSwap() {
    if (stack_.size() < 2) {
      last_error_ = DWARF_ERROR_STACK_INDEX_NOT_VALID;
      return false;
    }
    AddressType old_value = stack_[0];
    stack_[0] = stack_[1];
    stack_[1] = old_value;
    return true;
  }

  bool StackAt(size_t index, AddressType* value) {
    if (stack_.size() <= index) {
      last_error_ = DWARF_ERROR_STACK_INDEX_NOT_VALID;
      return false;
    }
    *value = stack_[index];
    return true;
  }

  size_t OperandsSize() { return operands_.size(); }
  size_t StackSize() { return stack_.size(); }

  bool Extract(uint64_t ip);

  bool GetOperand(const uint8_t& operand) {
    uint64_t value;
    if (!memory_->ReadEncodedValue(operand, &value)) {
      return false;
    }
    operands_.push_back(value);
    return true;
  }

 private:
  std::vector<AddressType> operands_;
  std::deque<AddressType> stack_;

  std::vector<AddressType> reg_loc_;

  DwarfMemory<AddressType>* memory_;

  void StackPushOperands() {
    for (auto operand : operands_) {
      stack_.push_front(operand);
    }
  }

  // Static functions implementing particular op types.
  static bool op_deref(void*) {
    return true;
  }

  static bool op_push(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->StackPushOperands();
    return true;
  }

  static bool op_dup(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType value;
    if (!dwarf->StackAt(0, &value)) {
      return false;
    }

    dwarf->StackPush(value);
    return true;
  }

  static bool op_drop(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    if (dwarf->StackSize() == 0) {
      return false;
    }
    dwarf->StackPop();
    return true;
  }

  static bool op_over(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType value;
    if (!dwarf->StackAt(1, &value)) {
      return false;
    }
    dwarf->StackPush(value);
    return true;
  }

  static bool op_pick(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    uint64_t index = dwarf->OperandAt(0);
    AddressType value;
    if (!dwarf->StackAt(index, &value)) {
      return false;
    }
    dwarf->StackPush(value);
    return true;
  }

  static bool op_swap(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    return dwarf->StackSwap();
  }

  static bool op_rot(void*) {
    return true;
  }

  static bool op_xderef(void*) {
    return true;
  }

  static bool op_abs(void*) {
    return true;
  }

  static bool op_and(void*) {
    return true;
  }

  static bool op_div(void*) {
    return true;
  }

  static bool op_minus(void*) {
    return true;
  }

  static bool op_mod(void*) {
    return true;
  }

  static bool op_mul(void*) {
    return true;
  }

  static bool op_neg(void*) {
    return true;
  }

  static bool op_not(void*) {
    return true;
  }

  static bool op_or(void*) {
    return true;
  }

  static bool op_plus(void*) {
    return true;
  }

  static bool op_plus_uconst(void*) {
    return true;
  }

  static bool op_shl(void*) {
    return true;
  }

  static bool op_shr(void*) {
    return true;
  }

  static bool op_shra(void*) {
    return true;
  }

  static bool op_xor(void*) {
    return true;
  }

  static bool op_bra(void*) {
    return true;
  }

  static bool op_eq(void*) {
    return true;
  }

  static bool op_ge(void*) {
    return true;
  }

  static bool op_gt(void*) {
    return true;
  }

  static bool op_le(void*) {
    return true;
  }

  static bool op_lt(void*) {
    return true;
  }

  static bool op_ne(void*) {
    return true;
  }

  static bool op_skip(void*) {
    return true;
  }

  static bool op_lit(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->StackPush(dwarf->cur_op() - 0x30);
    return true;
  }

  static bool op_reg(void*) {
    return true;
  }

  static bool op_breg(void*) {
    return true;
  }

  static bool op_regx(void*) {
    return true;
  }

  static bool op_fbreg(void*) {
    return true;
  }

  static bool op_bregx(void*) {
    return true;
  }

  static bool op_piece(void*) {
    return true;
  }

  static bool op_deref_size(void*) {
    return true;
  }

  static bool op_xderef_size(void*) {
    return true;
  }

  static bool op_push_object_address(void*) {
    return true;
  }

  static bool op_call2(void*) {
    return true;
  }

  static bool op_call4(void*) {
    return true;
  }

  static bool op_call_ref(void*) {
    return true;
  }

  static bool op_form_tls_address(void*) {
    return true;
  }

  static bool op_call_frame_cfa(void*) {
    return true;
  }

  static bool op_bit_piece(void*) {
    return true;
  }

  static bool op_implicit_value(void*) {
    return true;
  }

  static bool op_stack_value(void*) {
    return true;
  }

  static bool op_nop(void*) {
    return true;
  }

  constexpr static DwarfOpCallback kCallbackTable[256] = {
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
};
template<typename AddressType> constexpr DwarfOpCallback DwarfOp<AddressType>::kCallbackTable[256];

#endif  // _LIBANDROID_UNWIND_DWARF_OP_H
