/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <deque>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>

#include "DwarfError.h"
#include "DwarfMemory.h"
#include "DwarfOp.h"
#include "Log.h"
#include "Memory.h"
#include "Regs.h"

template <typename AddressType>
bool DwarfOp<AddressType>::Eval(uint64_t start, uint64_t end, uint8_t dwarf_version) {
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

template <typename AddressType>
bool DwarfOp<AddressType>::Decode(uint8_t dwarf_version) {
  last_error_ = DWARF_ERROR_NONE;
  if (!memory_->ReadBytes(&cur_op_, 1)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  const auto* op = &kCallbackTable[cur_op_];
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
    if (!memory_->ReadEncodedValue<AddressType>(op->operands[i], &value)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    operands_.push_back(value);
  }
  return op->handle_func(this);
}

template <typename AddressType>
void DwarfOp<AddressType>::GetLogInfo(uint64_t start, uint64_t end, std::vector<std::string>* lines) {
  memory_->set_cur_offset(start);
  while (memory_->cur_offset() < end) {
    uint8_t cur_op;
    if (!memory_->ReadBytes(&cur_op, 1)) {
      return;
    }

    std::string raw_string(android::base::StringPrintf("Raw Data: 0x%02x", cur_op));
    std::string log_string;
    const auto* op = &kCallbackTable[cur_op];
    if (op->handle_func == nullptr) {
      log_string = "Illegal";
    } else {
      log_string = op->name;
      uint64_t start_offset = memory_->cur_offset();
      for (size_t i = 0; i < op->num_operands; i++) {
        uint64_t value;
        if (!memory_->ReadEncodedValue<AddressType>(op->operands[i], &value)) {
          return;
        }
        log_string += ' ' + std::to_string(value);
      }
      uint64_t end_offset = memory_->cur_offset();

      memory_->set_cur_offset(start_offset);
      for (size_t i = start_offset; i < end_offset; i++) {
        uint8_t byte;
        if (!memory_->ReadBytes(&byte, 1)) {
          return;
        }
        raw_string += android::base::StringPrintf(" 0x%02x", byte);
      }
      memory_->set_cur_offset(end_offset);
    }
    lines->push_back(std::move(log_string));
    lines->push_back(std::move(raw_string));
  }
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_deref(DwarfOp<AddressType>* dwarf) {
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

template <typename AddressType>
bool DwarfOp<AddressType>::op_deref_size(DwarfOp<AddressType>* dwarf) {
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

template <typename AddressType>
bool DwarfOp<AddressType>::op_push(DwarfOp<AddressType>* dwarf) {
  // Push all of the operands.
  for (auto operand : dwarf->operands_) {
    dwarf->stack_.push_front(operand);
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_dup(DwarfOp<AddressType>* dwarf) {
  dwarf->stack_.push_front(dwarf->StackAt(0));
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_drop(DwarfOp<AddressType>* dwarf) {
  dwarf->StackPop();
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_over(DwarfOp<AddressType>* dwarf) {
  dwarf->stack_.push_front(dwarf->StackAt(1));
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_pick(DwarfOp<AddressType>* dwarf) {
  AddressType index = dwarf->OperandAt(0);
  if (index > dwarf->StackSize()) {
    dwarf->set_last_error(DWARF_ERROR_STACK_INDEX_NOT_VALID);
    return false;
  }
  dwarf->stack_.push_front(dwarf->StackAt(index));
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_swap(DwarfOp<AddressType>* dwarf) {
  AddressType old_value = dwarf->stack_[0];
  dwarf->stack_[0] = dwarf->stack_[1];
  dwarf->stack_[1] = old_value;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_rot(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->stack_[0];
  dwarf->stack_[0] = dwarf->stack_[1];
  dwarf->stack_[1] = dwarf->stack_[2];
  dwarf->stack_[2] = top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_abs(DwarfOp<AddressType>* dwarf) {
  SignedType signed_value = static_cast<SignedType>(dwarf->stack_[0]);
  if (signed_value < 0) {
    signed_value = -signed_value;
  }
  dwarf->stack_[0] = static_cast<AddressType>(signed_value);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_and(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] &= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_div(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (top == 0) {
    dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
    return false;
  }
  SignedType signed_divisor = static_cast<SignedType>(top);
  SignedType signed_dividend = static_cast<SignedType>(dwarf->stack_[0]);
  dwarf->stack_[0] = static_cast<AddressType>(signed_dividend / signed_divisor);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_minus(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] -= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_mod(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (top == 0) {
    dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
    return false;
  }
  dwarf->stack_[0] %= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_mul(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] *= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_neg(DwarfOp<AddressType>* dwarf) {
  SignedType signed_value = static_cast<SignedType>(dwarf->stack_[0]);
  dwarf->stack_[0] = static_cast<AddressType>(-signed_value);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_not(DwarfOp<AddressType>* dwarf) {
  dwarf->stack_[0] = ~dwarf->stack_[0];
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_or(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] |= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_plus(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] += top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_plus_uconst(DwarfOp<AddressType>* dwarf) {
  dwarf->stack_[0] += dwarf->OperandAt(0);;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_shl(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] <<= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_shr(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] >>= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_shra(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  SignedType signed_value = static_cast<SignedType>(dwarf->stack_[0]) >> top;
  dwarf->stack_[0] = static_cast<AddressType>(signed_value);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_xor(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  dwarf->stack_[0] ^= top;
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_bra(DwarfOp<AddressType>* dwarf) {
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

template <typename AddressType>
bool DwarfOp<AddressType>::op_eq(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (dwarf->stack_[0] == top) {
    dwarf->stack_[0] = 1;
  } else {
    dwarf->stack_[0] = 0;
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_ge(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (dwarf->stack_[0] >= top) {
    dwarf->stack_[0] = 1;
  } else {
    dwarf->stack_[0] = 0;
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_gt(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (dwarf->stack_[0] > top) {
    dwarf->stack_[0] = 1;
  } else {
    dwarf->stack_[0] = 0;
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_le(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (dwarf->stack_[0] <= top) {
    dwarf->stack_[0] = 1;
  } else {
    dwarf->stack_[0] = 0;
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_lt(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (dwarf->stack_[0] < top) {
    dwarf->stack_[0] = 1;
  } else {
    dwarf->stack_[0] = 0;
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_ne(DwarfOp<AddressType>* dwarf) {
  AddressType top = dwarf->StackPop();
  if (dwarf->stack_[0] != top) {
    dwarf->stack_[0] = 1;
  } else {
    dwarf->stack_[0] = 0;
  }
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_skip(DwarfOp<AddressType>* dwarf) {
  int16_t offset = static_cast<int16_t>(dwarf->OperandAt(0));
  uint64_t cur_offset = dwarf->memory_->cur_offset() + offset;
  dwarf->memory_->set_cur_offset(cur_offset);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_lit(DwarfOp<AddressType>* dwarf) {
  dwarf->stack_.push_front(dwarf->cur_op() - 0x30);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_reg(DwarfOp<AddressType>* dwarf) {
  dwarf->is_register_ = true;
  dwarf->stack_.push_front(dwarf->cur_op() - 0x50);
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_regx(DwarfOp<AddressType>* dwarf) {
  dwarf->is_register_ = true;
  dwarf->stack_.push_front(dwarf->OperandAt(0));
  return true;
}

// It's not clear for breg/bregx, if this op should read the current
// value of the register, or where we think that register is located.
// For simplicity, the code will read the value before doing the unwind.
template <typename AddressType>
bool DwarfOp<AddressType>::op_breg(DwarfOp<AddressType>* dwarf) {
  uint16_t reg = dwarf->cur_op() - 0x70;
  if (reg >= dwarf->regs_->total_regs()) {
    dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
    return false;
  }
  dwarf->stack_.push_front((*dwarf->regs_)[reg] + dwarf->OperandAt(0));
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_bregx(DwarfOp<AddressType>* dwarf) {
  AddressType reg = dwarf->OperandAt(0);
  if (reg >= dwarf->regs_->total_regs()) {
    dwarf->set_last_error(DWARF_ERROR_ILLEGAL_VALUE);
    return false;
  }
  dwarf->stack_.push_front((*dwarf->regs_)[reg] + dwarf->OperandAt(1));
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_nop(DwarfOp<AddressType>*) {
  return true;
}

template <typename AddressType>
bool DwarfOp<AddressType>::op_not_implemented(DwarfOp<AddressType>* dwarf) {
  dwarf->set_last_error(DWARF_ERROR_NOT_IMPLEMENTED);
  return false;
}

// Explicitly instantiate DwarfOp.
template class DwarfOp<uint32_t>;
template class DwarfOp<uint64_t>;
