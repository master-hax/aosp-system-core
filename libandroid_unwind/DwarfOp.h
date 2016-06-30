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

class DwarfOpBase;

struct DwarfOpCallback {
  bool (*handle_func)(DwarfOpBase*);
  uint8_t supported_version;
  uint8_t num_operands;
  uint8_t operands[2];
};

extern DwarfOpCallback g_opcode_table[256];
extern const char* g_opcode_names[256];

class DwarfOpBase {
 public:
  DwarfOpBase(Memory* regular_memory) : regular_memory_(regular_memory) { }
  virtual ~DwarfOpBase() = default;

  virtual uint64_t InternalOperandAt(size_t) = 0;
  virtual void InternalStackPushOperands() = 0;
  virtual void InternalStackPush(uint64_t) = 0;
  virtual bool InternalStackAt(size_t, uint64_t*) = 0;
  virtual uint64_t InternalStackTop() = 0;
  virtual uint64_t InternalStackPop() = 0;
  virtual bool InternalStackSwap() = 0;

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

    DwarfOpCallback* op = &g_opcode_table[cur_op_];
    if (op->handle_func == nullptr) {
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    // Check for an unsupported opcode.
    if (version < op->supported_version) {
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    for (size_t i = 0; i < op->num_operands; i++) {
      if (!GetOperand(op->operands[i])) {
        return false;
      }
    }
    return op->handle_func(this);
  }

  uint64_t InternalOperandAt(size_t index) override { return operands_[index]; }

  void InternalStackPushOperands() override {
    for (auto operand : operands_) {
      stack_.push_front(operand);
    }
  }

  void InternalStackPush(uint64_t value) override { stack_.push_front(value); }
  uint64_t InternalStackPop() override {
    AddressType value = stack_.front();
    stack_.pop_front();
    return value;
  }
  uint64_t InternalStackTop() override { return stack_.front(); }
  bool InternalStackSwap() override {
    if (stack_.size() < 2) {
      last_error_ = DWARF_ERROR_STACK_INDEX_NOT_VALID;
      return false;
    }
    AddressType old_value = stack_[0];
    stack_[0] = stack_[1];
    stack_[1] = old_value;
    return true;
  }

  bool InternalStackAt(size_t index, uint64_t* value) override {
    if (index < stack_.size()) {
      last_error_ = DWARF_ERROR_STACK_INDEX_NOT_VALID;
      return false;
    }
    *value = stack_[index];
    return true;
  }

  bool Extract(uint64_t ip);

  bool GetOperand(const uint8_t& operand) {
    uint64_t value;
    if (memory_->ReadEncodedValue(operand, &value)) {
      return false;
    }
    operands_.push_back(value);
    return true;
  }

  AddressType OperandAt(size_t index) { return static_cast<AddressType>(InternalOperandAt(index)); }
  AddressType StackTop() { return static_cast<AddressType>(InternalStackTop()); }

 private:
  std::vector<AddressType> operands_;
  std::deque<AddressType> stack_;

  std::vector<AddressType> reg_loc_;

  DwarfMemory<AddressType>* memory_;
};

#endif  // _LIBANDROID_UNWIND_DWARF_OP_H
