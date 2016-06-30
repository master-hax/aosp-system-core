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
#include <stdlib.h>

#include <deque>
#include <string>
#include <vector>

#include "DwarfMemory.h"
#include "DwarfError.h"
#include "Memory.h"
#include "Log.h"
#include "Regs.h"

enum DwarfVersion : uint8_t {
  DWARF_VERSION_2 = 2,
  DWARF_VERSION_3 = 3,
  DWARF_VERSION_4 = 4,
  DWARF_VERSION_MAX = DWARF_VERSION_4,
};

struct DwarfOpCallback {
  const char* name;
  bool (*handle_func)(void*);
  uint8_t supported_version;
  uint8_t num_required_stack_values;
  uint8_t num_operands;
  uint8_t operands[2];
};

template <typename AddressType>
class DwarfOp {
 public:
  DwarfOp(DwarfMemory<AddressType>* memory, Memory* regular_memory)
    : memory_(memory), regular_memory_(regular_memory) { }
  virtual ~DwarfOp() = default;

  DwarfError last_error() { return last_error_; }
  void set_last_error(DwarfError error) { last_error_ = error; }

  bool is_register() { return is_register_; }

  uint8_t cur_op() { return cur_op_; }

  Memory* regular_memory() { return regular_memory_; }

  AddressType OperandAt(size_t index) { return operands_[index]; }
  size_t OperandsSize() { return operands_.size(); }

  AddressType StackAt(size_t index) { return stack_[index]; }
  size_t StackSize() { return stack_.size(); }

  void set_regs(RegsTmpl<AddressType>* regs) { regs_ = regs; }

  bool Eval(uint64_t start, uint64_t end, uint8_t dwarf_version) {
    uint32_t iterations = 0;
    is_register_ = false;
    stack_.clear();
    memory_->set_cur_offset(start);
    while (memory_->cur_offset() < end) {
      if (!Decode(dwarf_version)) {
        return false;
      }
      // To protect against a branch that creates an infinite loop,
      // terminate if the number of iterations gets too high.
      if (iterations++ == 1000) {
        last_error_ = DWARF_ERROR_TOO_MANY_ITERATIONS;
        return false;
      }
    }
    return true;
  }

  bool Decode(uint8_t dwarf_version) {
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
    if (dwarf_version < op->supported_version) {
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    // Make sure that the required number of stack elements is available.
    if (stack_.size() < op->num_required_stack_values) {
      last_error_ = DWARF_ERROR_STACK_INDEX_NOT_VALID;
      return false;
    }

    operands_.clear();
    for (size_t i = 0; i < op->num_operands; i++) {
      uint64_t value;
      if (!memory_->ReadEncodedValue(op->operands[i], &value)) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
      operands_.push_back(value);
    }
    return op->handle_func(this);
  }

  void GetLogInfo(uint64_t start, uint64_t end, std::vector<std::string>* lines) {
    memory_->set_cur_offset(start);
    while (memory_->cur_offset() < end) {
      uint8_t cur_op;
      if (!memory_->ReadBytes(&cur_op, 1)) {
        return;
      }

      std::string raw_string(android::base::StringPrintf("Raw Data: 0x%02x", cur_op));
      std::string log_string;
      const DwarfOpCallback* op = &kCallbackTable[cur_op];
      if (op->handle_func == nullptr) {
        log_string = "Illegal";
      } else {
        log_string = op->name;
        uint64_t start_offset = memory_->cur_offset();
        for (size_t i = 0; i < op->num_operands; i++) {
          uint64_t value;
          if (!memory_->ReadEncodedValue(op->operands[i], &value)) {
            return;
          }
          log_string += ' ' + std::to_string(value);
        }
        uint64_t end_offset = memory_->cur_offset();
        for (size_t i = start_offset; i < end_offset; i++) {
          uint8_t byte;
          if (!memory_->ReadBytes(&byte, 1)) {
            return;
          }
          raw_string += android::base::StringPrintf(" 0x%02x", byte);
        }
        memory_->set_cur_offset(end_offset);
      }
      lines->push_back(log_string);
      lines->push_back(raw_string);
    }
  }

 private:
  DwarfMemory<AddressType>* memory_;
  Memory* regular_memory_;

  RegsTmpl<AddressType>* regs_;
  bool is_register_ = false;
  DwarfError last_error_ = DWARF_ERROR_NONE;
  uint8_t cur_op_;
  std::vector<AddressType> operands_;
  std::deque<AddressType> stack_;

  AddressType StackPop() {
    AddressType value = stack_.front();
    stack_.pop_front();
    return value;
  }

  // Static functions implementing particular op types.
  static bool op_deref(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    // Read the address and dereference it.
    AddressType addr = dwarf->StackPop();
    AddressType value;
    if (!dwarf->regular_memory()->Read(addr, &value, sizeof(value))) {
      dwarf->set_last_error(DWARF_ERROR_MEMORY_INVALID);
      return false;
    }
    dwarf->stack_.push_front(value);
    return true;
  }

  static bool op_deref_size(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType bytes_to_read = dwarf->OperandAt(0);
    if (bytes_to_read > sizeof(AddressType) || bytes_to_read == 0) {
      dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
      return false;
    }
    // Read the address and dereference it.
    AddressType addr = dwarf->StackPop();
    AddressType value = 0;
    if (!dwarf->regular_memory()->Read(addr, &value, bytes_to_read)) {
      dwarf->set_last_error(DWARF_ERROR_MEMORY_INVALID);
      return false;
    }
    dwarf->stack_.push_front(value);
    return true;
  }

  static bool op_push(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    // Push all of the operands.
    for (auto operand : dwarf->operands_) {
      dwarf->stack_.push_front(operand);
    }
    return true;
  }

  static bool op_dup(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->stack_.push_front(dwarf->StackAt(0));
    return true;
  }

  static bool op_drop(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->StackPop();
    return true;
  }

  static bool op_over(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->stack_.push_front(dwarf->StackAt(1));
    return true;
  }

  static bool op_pick(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType index = dwarf->OperandAt(0);
    if (index > dwarf->StackSize()) {
      dwarf->set_last_error(DWARF_ERROR_STACK_INDEX_NOT_VALID);
      return false;
    }
    dwarf->stack_.push_front(dwarf->StackAt(index));
    return true;
  }

  static bool op_swap(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType old_value = dwarf->stack_[0];
    dwarf->stack_[0] = dwarf->stack_[1];
    dwarf->stack_[1] = old_value;
    return true;
  }

  static bool op_rot(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->stack_[0];
    dwarf->stack_[0] = dwarf->stack_[1];
    dwarf->stack_[1] = dwarf->stack_[2];
    dwarf->stack_[2] = top;
    return true;
  }

  static bool op_abs(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    if (sizeof(AddressType) == 4) {
      int32_t signed_value = static_cast<int32_t>(dwarf->stack_[0]);
      dwarf->stack_[0] = abs(signed_value);
    } else {
      int64_t signed_value = static_cast<int64_t>(dwarf->stack_[0]);
      dwarf->stack_[0] = llabs(signed_value);
    }
    return true;
  }

  static bool op_and(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] &= top;
    return true;
  }

  static bool op_div(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (top == 0) {
      dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
      return false;
    }
    if (sizeof(AddressType) == 4) {
      int32_t signed_top = static_cast<int32_t>(top);
      dwarf->stack_[0] = static_cast<int32_t>(dwarf->stack_[0]) / signed_top;
    } else {
      int64_t signed_top = static_cast<int64_t>(top);
      dwarf->stack_[0] = static_cast<int64_t>(dwarf->stack_[0]) / signed_top;
    }
    return true;
  }

  static bool op_minus(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] -= top;
    return true;
  }

  static bool op_mod(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (top == 0) {
      dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
      return false;
    }
    dwarf->stack_[0] %= top;
    return true;
  }

  static bool op_mul(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] *= top;
    return true;
  }

  static bool op_neg(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    if (sizeof(AddressType) == 4) {
      int32_t signed_value = static_cast<int32_t>(dwarf->stack_[0]);
      dwarf->stack_[0] = -signed_value;
    } else {
      int64_t signed_value = static_cast<int64_t>(dwarf->stack_[0]);
      dwarf->stack_[0] = -signed_value;
    }
    return true;
  }

  static bool op_not(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->stack_[0] = ~dwarf->stack_[0];
    return true;
  }

  static bool op_or(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] |= top;
    return true;
  }

  static bool op_plus(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] += top;
    return true;
  }

  static bool op_plus_uconst(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->stack_[0] += dwarf->OperandAt(0);;
    return true;
  }

  static bool op_shl(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] <<= top;
    return true;
  }

  static bool op_shr(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] >>= top;
    return true;
  }

  static bool op_shra(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (sizeof(AddressType) == 4) {
      int32_t signed_value = static_cast<int32_t>(dwarf->stack_[0]) >> top;
      dwarf->stack_[0] = signed_value;
    } else {
      int64_t signed_value = static_cast<int64_t>(dwarf->stack_[0]) >> top;
      dwarf->stack_[0] = signed_value;
    }
    return true;
  }

  static bool op_xor(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    dwarf->stack_[0] ^= top;
    return true;
  }

  static bool op_bra(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    // Requires one stack element.
    AddressType top = dwarf->StackPop();
    if (top != 0) {
      int16_t offset = static_cast<int16_t>(dwarf->OperandAt(0));
      uint64_t cur_offset = dwarf->memory_->cur_offset() + offset;
      dwarf->memory_->set_cur_offset(cur_offset);
    } else {
      int16_t offset = static_cast<int16_t>(dwarf->OperandAt(0));
      uint64_t cur_offset = dwarf->memory_->cur_offset() - offset;
      dwarf->memory_->set_cur_offset(cur_offset);
    }
    return true;
  }

  static bool op_eq(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (dwarf->stack_[0] == top) {
      dwarf->stack_[0] = 1;
    } else {
      dwarf->stack_[0] = 0;
    }
    return true;
  }

  static bool op_ge(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (dwarf->stack_[0] >= top) {
      dwarf->stack_[0] = 1;
    } else {
      dwarf->stack_[0] = 0;
    }
    return true;
  }

  static bool op_gt(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (dwarf->stack_[0] > top) {
      dwarf->stack_[0] = 1;
    } else {
      dwarf->stack_[0] = 0;
    }
    return true;
  }

  static bool op_le(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (dwarf->stack_[0] <= top) {
      dwarf->stack_[0] = 1;
    } else {
      dwarf->stack_[0] = 0;
    }
    return true;
  }

  static bool op_lt(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (dwarf->stack_[0] < top) {
      dwarf->stack_[0] = 1;
    } else {
      dwarf->stack_[0] = 0;
    }
    return true;
  }

  static bool op_ne(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType top = dwarf->StackPop();
    if (dwarf->stack_[0] != top) {
      dwarf->stack_[0] = 1;
    } else {
      dwarf->stack_[0] = 0;
    }
    return true;
  }

  static bool op_skip(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    int16_t offset = static_cast<int16_t>(dwarf->OperandAt(0));
    uint64_t cur_offset = dwarf->memory_->cur_offset() + offset;
    dwarf->memory_->set_cur_offset(cur_offset);
    return true;
  }

  static bool op_lit(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->stack_.push_front(dwarf->cur_op() - 0x30);
    return true;
  }

  static bool op_reg(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->is_register_ = true;
    dwarf->stack_.push_front(dwarf->cur_op() - 0x50);
    return true;
  }

  static bool op_regx(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->is_register_ = true;
    dwarf->stack_.push_front(dwarf->OperandAt(0));
    return true;
  }

  // It's not clear for breg/bregx, if this op should read the current
  // value of the register, or where we think that register is located.
  // For simplicity, the code will read the value before doing the unwind.
  static bool op_breg(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    uint16_t reg = dwarf->cur_op() - 0x70;
    if (reg >= dwarf->regs_->total_regs()) {
      dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
      return false;
    }
    dwarf->stack_.push_front(dwarf->regs_->value(reg) + dwarf->OperandAt(0));
    return true;
  }

  static bool op_bregx(void* ptr) {
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    AddressType reg = dwarf->OperandAt(0);
    if (reg >= dwarf->regs_->total_regs()) {
      dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
      return false;
    }
    dwarf->stack_.push_front(dwarf->regs_->value(reg) + dwarf->OperandAt(1));
    return true;
  }

  static bool op_nop(void*) {
    return true;
  }

  static bool op_not_implemented(void* ptr) {
    // Not going to implement this.
    DwarfOp* dwarf = reinterpret_cast<DwarfOp*>(ptr);
    dwarf->set_last_error(DWARF_ERROR_NOT_IMPLEMENTED);
    return false;
  }

  constexpr static DwarfOpCallback kCallbackTable[256] = {
    { nullptr, nullptr, 0, 0, 0, {} },    // 0x00 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0x01 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0x02 illegal op
    {                                     // 0x03 DW_OP_addr
      "DW_OP_addr",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_absptr },
    },
    { nullptr, nullptr, 0, 0, 0, {} },    // 0x04 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0x05 illegal op
    {                                     // 0x06 DW_OP_deref
      "DW_OP_deref",
      op_deref,
      DWARF_VERSION_2,
      1,
      0,
      {},
    },
    { nullptr, nullptr, 0, 0, 0, {} },    // 0x07 illegal op
    {                                     // 0x08 DW_OP_const1u
      "DW_OP_const1u",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_udata1 },
    },
    {                                     // 0x09 DW_OP_const1s
      "DW_OP_const1s",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sdata1 },
    },
    {                                     // 0x0a DW_OP_const2u
      "DW_OP_const2u",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_udata2 },
    },
    {                                     // 0x0b DW_OP_const2s
      "DW_OP_const2s",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sdata2 },
    },
    {                                     // 0x0c DW_OP_const4u
      "DW_OP_const4u",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_udata4 },
    },
    {                                     // 0x0d DW_OP_const4s
      "DW_OP_const4s",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sdata4 },
    },
    {                                     // 0x0e DW_OP_const8u
      "DW_OP_const8u",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_udata8 },
    },
    {                                     // 0x0f DW_OP_const8s
      "DW_OP_const8s",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sdata8 },
    },
    {                                     // 0x10 DW_OP_constu
      "DW_OP_constu",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                                     // 0x11 DW_OP_consts
      "DW_OP_consts",
      op_push,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x12 DW_OP_dup
      "DW_OP_dup",
      op_dup,
      DWARF_VERSION_2,
      1,
      0,
      {},
    },
    {                                     // 0x13 DW_OP_drop
      "DW_OP_drop",
      op_drop,
      DWARF_VERSION_2,
      1,
      0,
      {},
    },
    {                                     // 0x14 DW_OP_over
      "DW_OP_over",
      op_over,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x15 DW_OP_pick
      "DW_OP_pick",
      op_pick,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_udata1 },
    },
    {                                     // 0x16 DW_OP_swap
      "DW_OP_swap",
      op_swap,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x17 DW_OP_rot
      "DW_OP_rot",
      op_rot,
      DWARF_VERSION_2,
      3,
      0,
      {},
    },
    {                                     // 0x18 DW_OP_xderef
      "DW_OP_xderef",
      op_not_implemented,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x19 DW_OP_abs
      "DW_OP_abs",
      op_abs,
      DWARF_VERSION_2,
      1,
      0,
      {},
    },
    {                                     // 0x1a DW_OP_and
      "DW_OP_and",
      op_and,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x1b DW_OP_div
      "DW_OP_div",
      op_div,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x1c DW_OP_minus
      "DW_OP_minus",
      op_minus,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x1d DW_OP_mod
      "DW_OP_mod",
      op_mod,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x1e DW_OP_mul
      "DW_OP_mul",
      op_mul,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x1f DW_OP_neg
      "DW_OP_neg",
      op_neg,
      DWARF_VERSION_2,
      1,
      0,
      {},
    },
    {                                     // 0x20 DW_OP_not
      "DW_OP_not",
      op_not,
      DWARF_VERSION_2,
      1,
      0,
      {},
    },
    {                                     // 0x21 DW_OP_or
      "DW_OP_or",
      op_or,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x22 DW_OP_plus
      "DW_OP_plus",
      op_plus,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x23 DW_OP_plus_uconst
      "DW_OP_plus_uconst",
      op_plus_uconst,
      DWARF_VERSION_2,
      1,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                                     // 0x24 DW_OP_shl
      "DW_OP_shl",
      op_shl,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x25 DW_OP_shr
      "DW_OP_shr",
      op_shr,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x26 DW_OP_shra
      "DW_OP_shra",
      op_shra,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x27 DW_OP_xor
      "DW_OP_xor",
      op_xor,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x28 DW_OP_bra
      "DW_OP_bra",
      op_bra,
      DWARF_VERSION_2,
      1,
      1,
      { DW_EH_PE_sdata2 },
    },
    {                                     // 0x29 DW_OP_eq
      "DW_OP_eq",
      op_eq,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x2a DW_OP_ge
      "DW_OP_ge",
      op_ge,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x2b DW_OP_gt
      "DW_OP_gt",
      op_gt,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x2c DW_OP_le
      "DW_OP_le",
      op_le,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x2d DW_OP_lt
      "DW_OP_lt",
      op_lt,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x2e DW_OP_ne
      "DW_OP_ne",
      op_ne,
      DWARF_VERSION_2,
      2,
      0,
      {},
    },
    {                                     // 0x2f DW_OP_skip
      "DW_OP_skip",
      op_skip,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sdata2 },
    },
    {                                     // 0x30 DW_OP_lit0
      "DW_OP_lit0",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x31 DW_OP_lit1
      "DW_OP_lit1",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x32 DW_OP_lit2
      "DW_OP_lit2",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x33 DW_OP_lit3
      "DW_OP_lit3",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x34 DW_OP_lit4
      "DW_OP_lit4",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x35 DW_OP_lit5
      "DW_OP_lit5",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x36 DW_OP_lit6
      "DW_OP_lit6",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x37 DW_OP_lit7
      "DW_OP_lit7",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x38 DW_OP_lit8
      "DW_OP_lit8",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x39 DW_OP_lit9
      "DW_OP_lit9",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x3a DW_OP_lit10
      "DW_OP_lit10",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x3b DW_OP_lit11
      "DW_OP_lit11",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x3c DW_OP_lit12
      "DW_OP_lit12",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x3d DW_OP_lit13
      "DW_OP_lit13",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x3e DW_OP_lit14
      "DW_OP_lit14",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x3f DW_OP_lit15
      "DW_OP_lit15",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x40 DW_OP_lit16
      "DW_OP_lit16",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x41 DW_OP_lit17
      "DW_OP_lit17",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x42 DW_OP_lit18
      "DW_OP_lit18",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x43 DW_OP_lit19
      "DW_OP_lit19",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x44 DW_OP_lit20
      "DW_OP_lit20",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x45 DW_OP_lit21
      "DW_OP_lit21",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x46 DW_OP_lit22
      "DW_OP_lit22",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x47 DW_OP_lit23
      "DW_OP_lit23",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x48 DW_OP_lit24
      "DW_OP_lit24",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x49 DW_OP_lit25
      "DW_OP_lit25",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x4a DW_OP_lit26
      "DW_OP_lit26",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x4b DW_OP_lit27
      "DW_OP_lit27",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x4c DW_OP_lit28
      "DW_OP_lit28",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x4d DW_OP_lit29
      "DW_OP_lit29",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x4e DW_OP_lit30
      "DW_OP_lit30",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x4f DW_OP_lit31
      "DW_OP_lit31",
      op_lit,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x50 DW_OP_reg0
      "DW_OP_reg0",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x51 DW_OP_reg1
      "DW_OP_reg1",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x52 DW_OP_reg2
      "DW_OP_reg2",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x53 DW_OP_reg3
      "DW_OP_reg3",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x54 DW_OP_reg4
      "DW_OP_reg4",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x55 DW_OP_reg5
      "DW_OP_reg5",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x56 DW_OP_reg6
      "DW_OP_reg6",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x57 DW_OP_reg7
      "DW_OP_reg7",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x58 DW_OP_reg8
      "DW_OP_reg8",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x59 DW_OP_reg9
      "DW_OP_reg9",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x5a DW_OP_reg10
      "DW_OP_reg10",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x5b DW_OP_reg11
      "DW_OP_reg11",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x5c DW_OP_reg12
      "DW_OP_reg12",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x5d DW_OP_reg13
      "DW_OP_reg13",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x5e DW_OP_reg14
      "DW_OP_reg14",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x5f DW_OP_reg15
      "DW_OP_reg15",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x60 DW_OP_reg16
      "DW_OP_reg16",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x61 DW_OP_reg17
      "DW_OP_reg17",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x62 DW_OP_reg18
      "DW_OP_reg18",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x63 DW_OP_reg19
      "DW_OP_reg19",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x64 DW_OP_reg20
      "DW_OP_reg20",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x65 DW_OP_reg21
      "DW_OP_reg21",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x66 DW_OP_reg22
      "DW_OP_reg22",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x67 DW_OP_reg23
      "DW_OP_reg23",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x68 DW_OP_reg24
      "DW_OP_reg24",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x69 DW_OP_reg25
      "DW_OP_reg25",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x6a DW_OP_reg26
      "DW_OP_reg26",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x6b DW_OP_reg27
      "DW_OP_reg27",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x6c DW_OP_reg28
      "DW_OP_reg28",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x6d DW_OP_reg29
      "DW_OP_reg29",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x6e DW_OP_reg30
      "DW_OP_reg30",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x6f DW_OP_reg31
      "DW_OP_reg31",
      op_reg,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x70 DW_OP_breg0
      "DW_OP_breg0",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x71 DW_OP_breg1
      "DW_OP_breg1",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x72 DW_OP_breg2
      "DW_OP_breg2",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x73 DW_OP_breg3
      "DW_OP_breg3",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x74 DW_OP_breg4
      "DW_OP_breg4",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x75 DW_OP_breg5
      "DW_OP_breg5",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x76 DW_OP_breg6
      "DW_OP_breg6",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x77 DW_OP_breg7
      "DW_OP_breg7",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x78 DW_OP_breg8
      "DW_OP_breg8",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x79 DW_OP_breg9
      "DW_OP_breg9",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x7a DW_OP_breg10
      "DW_OP_breg10",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x7b DW_OP_breg11
      "DW_OP_breg11",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x7c DW_OP_breg12
      "DW_OP_breg12",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x7d DW_OP_breg13
      "DW_OP_breg13",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x7e DW_OP_breg14
      "DW_OP_breg14",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x7f DW_OP_breg15
      "DW_OP_breg15",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x80 DW_OP_breg16
      "DW_OP_breg16",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x81 DW_OP_breg17
      "DW_OP_breg17",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x82 DW_OP_breg18
      "DW_OP_breg18",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x83 DW_OP_breg19
      "DW_OP_breg19",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x84 DW_OP_breg20
      "DW_OP_breg20",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x85 DW_OP_breg21
      "DW_OP_breg21",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x86 DW_OP_breg22
      "DW_OP_breg22",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x87 DW_OP_breg23
      "DW_OP_breg23",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x88 DW_OP_breg24
      "DW_OP_breg24",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x89 DW_OP_breg25
      "DW_OP_breg25",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x8a DW_OP_breg26
      "DW_OP_breg26",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x8b DW_OP_breg27
      "DW_OP_breg27",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x8c DW_OP_breg28
      "DW_OP_breg28",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x8d DW_OP_breg29
      "DW_OP_breg29",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x8e DW_OP_breg30
      "DW_OP_breg30",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x8f DW_OP_breg31
      "DW_OP_breg31",
      op_breg,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x90 DW_OP_regx
      "DW_OP_regx",
      op_regx,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                                     // 0x91 DW_OP_fbreg
      "DW_OP_fbreg",
      op_not_implemented,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_sleb128 },
    },
    {                                     // 0x92 DW_OP_bregx
      "DW_OP_bregx",
      op_bregx,
      DWARF_VERSION_2,
      0,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_sleb128 },
    },
    {                                     // 0x93 DW_OP_piece
      "DW_OP_piece",
      op_not_implemented,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                                     // 0x94 DW_OP_deref_size
      "DW_OP_deref_size",
      op_deref_size,
      DWARF_VERSION_2,
      1,
      1,
      { DW_EH_PE_udata1 },
    },
    {                                     // 0x95 DW_OP_xderef_size
      "DW_OP_xderef_size",
      op_not_implemented,
      DWARF_VERSION_2,
      0,
      1,
      { DW_EH_PE_udata1 },
    },
    {                                     // 0x96 DW_OP_nop
      "DW_OP_nop",
      op_nop,
      DWARF_VERSION_2,
      0,
      0,
      {},
    },
    {                                     // 0x97 DW_OP_push_object_address
      "DW_OP_push_object_address",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      0,
      {},
    },
    {                                     // 0x98 DW_OP_call2
      "DW_OP_call2",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      1,
      { DW_EH_PE_udata2 },
    },
    {                                     // 0x99 DW_OP_call4
      "DW_OP_call4",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      1,
      { DW_EH_PE_udata4 },
    },
    {                                     // 0x9a DW_OP_call_ref
      "DW_OP_call_ref",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      0, // Has a different sized operand (4 bytes or 8 bytes).
      {},
    },
    {                                     // 0x9b DW_OP_form_tls_address
      "DW_OP_form_tls_address",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      0,
      {},
    },
    {                                     // 0x9c DW_OP_call_frame_cfa
      "DW_OP_call_frame_cfa",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      0,
      {},
    },
    {                                     // 0x9d DW_OP_bit_piece
      "DW_OP_bit_piece",
      op_not_implemented,
      DWARF_VERSION_3,
      0,
      2,
      { DW_EH_PE_uleb128, DW_EH_PE_uleb128 },
    },
    {                                     // 0x9e DW_OP_implicit_value
      "DW_OP_implicit_value",
      op_not_implemented,
      DWARF_VERSION_4,
      0,
      1,
      { DW_EH_PE_uleb128 },
    },
    {                                     // 0x9f DW_OP_stack_value
      "DW_OP_stack_value",
      op_not_implemented,
      DWARF_VERSION_4,
      1,
      0,
      {},
    },
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa0 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa1 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa2 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa3 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa4 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa5 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa6 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa7 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa8 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xa9 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xaa illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xab illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xac illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xad illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xae illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xaf illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb0 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb1 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb2 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb3 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb4 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb5 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb6 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb7 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb8 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xb9 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xba illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xbb illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xbc illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xbd illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xbe illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xbf illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc0 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc1 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc2 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc3 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc4 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc5 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc6 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc7 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc8 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xc9 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xca illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xcb illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xcc illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xcd illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xce illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xcf illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd0 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd1 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd2 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd3 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd4 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd5 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd6 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd7 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd8 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xd9 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xda illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xdb illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xdc illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xdd illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xde illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xdf illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe0 DW_OP_lo_user
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe1 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe2 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe3 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe4 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe5 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe6 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe7 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe8 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xe9 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xea illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xeb illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xec illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xed illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xee illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xef illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf0 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf1 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf2 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf3 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf4 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf5 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf6 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf7 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf8 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xf9 illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xfa illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xfb illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xfc illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xfd illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xfe illegal op
    { nullptr, nullptr, 0, 0, 0, {} },    // 0xff DW_OP_hi_user
  };
};
template<typename AddressType> constexpr DwarfOpCallback DwarfOp<AddressType>::kCallbackTable[256];

#endif  // _LIBANDROID_UNWIND_DWARF_OP_H
