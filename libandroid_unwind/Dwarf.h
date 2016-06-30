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

#ifndef _LIBANDROID_UNWIND_DWARF_H
#define _LIBANDROID_UNWIND_DWARF_H

#include <stdint.h>

#include <vector>
#include <deque>

#include "Memory.h"

class Dwarf;

enum DwarfError : uint8_t {
  DWARF_ERROR_NONE,
  DWARF_ERROR_MEMORY_INVALID,
  DWARF_ERROR_ILLEGAL_OPCODE,
  DWARF_ERROR_STACK_INDEX_NOT_VALID,
};

enum DwarfOperand : uint8_t {
  DWARF_OPERAND_1_BYTE_SIGNED,
  DWARF_OPERAND_1_BYTE_UNSIGNED,
  DWARF_OPERAND_2_BYTES_SIGNED,
  DWARF_OPERAND_2_BYTES_UNSIGNED,
  DWARF_OPERAND_4_BYTES_SIGNED,
  DWARF_OPERAND_4_BYTES_UNSIGNED,
  DWARF_OPERAND_8_BYTES_SIGNED,
  DWARF_OPERAND_8_BYTES_UNSIGNED,
  DWARF_OPERAND_ULEB128,
  DWARF_OPERAND_SLEB128,
  DWARF_OPERAND_ADDRESS,
};

struct DwarfCallback {
  bool (*handle_func)(Dwarf*);
  uint8_t supported_version;
  uint8_t num_operands;
  DwarfOperand operands[2];
};

extern DwarfCallback g_opcode_table[256];
extern const char* g_opcode_names[256];

extern DwarfCallback g_cfa_table[64];
extern const char* g_cfa_names[64];

class Dwarf {
 public:
  Dwarf(Memory* op_memory, Memory* regular_memory, umaxptr_t op_offset, uint8_t version)
    : op_memory_(op_memory), regular_memory_(regular_memory), op_offset_(op_offset), version_(version) { }
  virtual ~Dwarf() = default;

  virtual umaxptr_t InternalOperandAt(size_t) = 0;
  virtual void InternalStackPushOperands() = 0;
  virtual void InternalStackPush(umaxptr_t) = 0;
  virtual bool InternalStackAt(size_t, umaxptr_t*) = 0;
  virtual umaxptr_t InternalStackTop() = 0;
  virtual umaxptr_t InternalStackPop() = 0;
  virtual bool InternalStackSwap() = 0;

  uint8_t version() { return version_; }
  uint8_t cur_op() { return cur_op_; }
  DwarfError last_error() { return last_error_; }
  umaxptr_t op_offset() { return op_offset_; }

  virtual bool EvalOpcode() = 0;

 protected:
  Memory* op_memory_;
  Memory* regular_memory_;
  umaxptr_t op_offset_;
  uint8_t version_;
  uint8_t cur_op_;
  DwarfError last_error_;
};

template <typename AddressType>
class DwarfTemplate : public Dwarf {
 public:
  DwarfTemplate(Memory* op_memory, Memory* regular_memory, umaxptr_t op_offset, uint8_t version)
    : Dwarf(op_memory, regular_memory, op_offset, version) { }
  virtual ~DwarfTemplate() = default;

  bool EvalOpcode() override {
    last_error_ = DWARF_ERROR_NONE;
    if (!GetOpBytes(&cur_op_, 1)) {
      return false;
    }

    DwarfCallback* op = &g_opcode_table[cur_op_];
    if (op->handle_func == nullptr) {
      last_error_ = DWARF_ERROR_ILLEGAL_OPCODE;
      return false;
    }

    // Check for an unsupported opcode.
    if (version() < op->supported_version) {
      last_error_ = DWARF_ERROR_ILLEGAL_OPCODE;
      return false;
    }

    for (size_t i = 0; i < op->num_operands; i++) {
      if (!GetOperand(op->operands[i])) {
        return false;
      }
    }
    return op->handle_func(this);
  }

  umaxptr_t InternalOperandAt(size_t index) override { return operands_[index]; }

  void InternalStackPushOperands() override {
    for (auto operand : operands_) {
      stack_.push_front(operand);
    }
  }

  void InternalStackPush(umaxptr_t value) override { stack_.push_front(value); }
  umaxptr_t InternalStackPop() override {
    AddressType value = stack_.front();
    stack_.pop_front();
    return value;
  }
  umaxptr_t InternalStackTop() override { return stack_.front(); }
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

  bool InternalStackAt(size_t index, umaxptr_t* value) override {
    if (index < stack_.size()) {
      last_error_ = DWARF_ERROR_STACK_INDEX_NOT_VALID;
      return false;
    }
    *value = stack_[index];
    return true;
  }

  template <typename SignedType>
  bool GetSigned(AddressType* value) {
    SignedType signed_value;
    if (!GetOpBytes(&signed_value, sizeof(SignedType))) {
      return false;
    }
    // Sign extend the value if necessary.
    if (sizeof(AddressType) == 4) {
      *value = static_cast<int32_t>(signed_value);
    } else {
      *value = static_cast<int64_t>(signed_value);
    }
    return true;
  }

  bool Extract(umaxptr_t ip);

  bool Decode();

  bool GetOperand(const DwarfOperand& operand) {
    bool valid = true;
    AddressType value;
    switch(operand) {
    case DWARF_OPERAND_1_BYTE_SIGNED:
      valid = GetSigned<int8_t>(&value);
      break;
    case DWARF_OPERAND_2_BYTES_SIGNED:
      valid = GetSigned<int16_t>(&value);
      break;
    case DWARF_OPERAND_4_BYTES_SIGNED:
      valid = GetSigned<int32_t>(&value);
      break;
    case DWARF_OPERAND_8_BYTES_SIGNED:
      if (sizeof(AddressType) < 8) {
        int64_t value64;
        valid = GetOpBytes(&value64, 8);
        if (valid) {
          // Truncate the value.
          value = static_cast<AddressType>(value64);
        }
      } else {
        valid = GetOpBytes(&value, 8);
      }
      break;
    case DWARF_OPERAND_1_BYTE_UNSIGNED:
      valid = GetOpBytes(&value, 1);
      break;
    case DWARF_OPERAND_2_BYTES_UNSIGNED:
      valid = GetOpBytes(&value, 2);
      break;
    case DWARF_OPERAND_4_BYTES_UNSIGNED:
      valid = GetOpBytes(&value, 4);
      break;
    case DWARF_OPERAND_8_BYTES_UNSIGNED:
      if (sizeof(AddressType) < 8) {
        uint64_t value64;
        valid = GetOpBytes(&value64, 8);
        if (valid) {
          // Truncate the value.
          value = static_cast<AddressType>(value64);
        }
      } else {
        valid = GetOpBytes(&value, 8);
      }
      break;
    case DWARF_OPERAND_ADDRESS:
      valid = GetOpBytes(&value, sizeof(AddressType));
      break;
    case DWARF_OPERAND_ULEB128:
      {
        value = 0;
        AddressType shift = 0;
        uint8_t byte;
        do {
          if (!GetOpBytes(&byte, 1)) {
            return false;
          }
          value |= static_cast<AddressType>(byte & 0x7f) << shift;
          shift += 7;
        } while (byte & 0x80);
      }
      break;
    case DWARF_OPERAND_SLEB128:
      {
        value = 0;
        AddressType shift = 0;
        uint8_t byte;
        do {
          if (!GetOpBytes(&byte, 1)) {
            return false;
          }
          value |= static_cast<AddressType>(byte & 0x7f) << shift;
          shift += 7;
        } while (byte & 0x80);
        if (byte & 0x40) {
          // Negative value, need to sign extend.
          value |= static_cast<AddressType>(-1) << shift;
        }
      }
      break;
    }
    if (valid) {
      operands_.push_back(value);
    }
    return valid;
  }

  inline bool GetOpBytes(void* dst, size_t bytes) {
    bool valid = op_memory_->Read(op_offset_, dst, bytes);
    op_offset_ += bytes;
    if (!valid) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
    }
    return valid;
  }

 private:
  std::vector<AddressType> operands_;
  std::deque<AddressType> stack_;

  std::vector<AddressType> reg_loc_;
};

class Dwarf32 : public DwarfTemplate<uint32_t> {
 public:
  Dwarf32(Memory* op_memory, Memory* regular_memory, umaxptr_t offset, uint8_t version)
    : DwarfTemplate(op_memory, regular_memory, offset, version) { }
  virtual ~Dwarf32() = default;

  uint32_t OperandAt(size_t index) { return static_cast<uint32_t>(InternalOperandAt(index)); }
  void StackPush(uint32_t value) { InternalStackPush(value); }
  bool StackAt(size_t index, uint32_t* value) {
    umaxptr_t value_max;
    bool return_value = InternalStackAt(index, &value_max);
    *value = static_cast<uint32_t>(value_max);
    return return_value;
  }
  uint32_t StackTop() { return InternalStackTop(); }
  uint32_t StackPop() { return InternalStackPop(); }
};

class Dwarf64 : public DwarfTemplate<uint64_t> {
 public:
  Dwarf64(Memory* op_memory, Memory* regular_memory, umaxptr_t op_offset, uint8_t version)
    : DwarfTemplate(op_memory, regular_memory, op_offset, version) { }
  virtual ~Dwarf64() = default;

  uint64_t OperandAt(size_t index) { return static_cast<uint32_t>(InternalOperandAt(index)); }
  void StackPush(uint64_t value) { InternalStackPush(value); }
  bool StackAt(size_t index, uint64_t* value) { return InternalStackAt(index, value); }
  uint64_t StackTop() { return InternalStackTop(); }
  uint64_t StackPop() { return InternalStackPop(); }
};

#endif  // _LIBANDROID_UNWIND_DWARF_H
