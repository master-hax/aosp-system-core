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

#ifndef _LIBANDROID_UNWIND_REGS_H
#define _LIBANDROID_UNWIND_REGS_H

#include <stdint.h>

enum ArmReg : uint16_t {
  ARM_REG_R0 = 0,
  ARM_REG_R1,
  ARM_REG_R2,
  ARM_REG_R3,
  ARM_REG_R4,
  ARM_REG_R5,
  ARM_REG_R6,
  ARM_REG_R7,
  ARM_REG_R8,
  ARM_REG_R9,
  ARM_REG_R10,
  ARM_REG_R11,
  ARM_REG_R12,
  ARM_REG_R13,
  ARM_REG_R14,
  ARM_REG_R15,

  ARM_REG_SP = ARM_REG_R13,
  ARM_REG_LR = ARM_REG_R14,
  ARM_REG_PC = ARM_REG_R15,
};

enum Arm64Reg : uint16_t {
  ARM64_REG_R0 = 0,
  ARM64_REG_R1,
  ARM64_REG_R2,
  ARM64_REG_R3,
  ARM64_REG_R4,
  ARM64_REG_R5,
  ARM64_REG_R6,
  ARM64_REG_R7,
  ARM64_REG_R8,
  ARM64_REG_R9,
  ARM64_REG_R10,
  ARM64_REG_R11,
  ARM64_REG_R12,
  ARM64_REG_R13,
  ARM64_REG_R14,
  ARM64_REG_R15,
  ARM64_REG_R16,
  ARM64_REG_R17,
  ARM64_REG_R18,
  ARM64_REG_R19,
  ARM64_REG_R20,
  ARM64_REG_R21,
  ARM64_REG_R22,
  ARM64_REG_R23,
  ARM64_REG_R24,
  ARM64_REG_R25,
  ARM64_REG_R26,
  ARM64_REG_R27,
  ARM64_REG_R28,
  ARM64_REG_R29,
  ARM64_REG_R30,
  ARM64_REG_R31,
  ARM64_REG_PC,

  ARM64_REG_SP = ARM64_REG_R30,
  ARM64_REG_LR = ARM64_REG_R31,
};

enum X86Reg : uint16_t {
  X86_REG_GS = 0,
  X86_REG_FS,
  X86_REG_ES,
  X86_REG_DS,
  X86_REG_EDI,
  X86_REG_ESI,
  X86_REG_EBP,
  X86_REG_ESP,
  X86_REG_EBX,
  X86_REG_EDX,
  X86_REG_ECX,
  X86_REG_EAX,
  X86_REG_TRAPNO,
  X86_REG_ERR,
  X86_REG_EIP,
  X86_REG_CS,
  X86_REG_EFL,
  X86_REG_UESP,
  X86_REG_SS,

  X86_REG_SP = X86_REG_ESP,
  X86_REG_PC = X86_REG_EIP,
};

enum X86_64Reg : uint16_t {
  X86_64_REG_R8 = 0,
  X86_64_REG_R9,
  X86_64_REG_R10,
  X86_64_REG_R11,
  X86_64_REG_R12,
  X86_64_REG_R13,
  X86_64_REG_R14,
  X86_64_REG_R15,
  X86_64_REG_RDI,
  X86_64_REG_RSI,
  X86_64_REG_RBP,
  X86_64_REG_RBX,
  X86_64_REG_RDX,
  X86_64_REG_RAX,
  X86_64_REG_RCX,
  X86_64_REG_RSP,
  X86_64_REG_RIP,
  X86_64_REG_EFL,
  X86_64_REG_CSGSFS,
  X86_64_REG_ERR,
  X86_64_REG_TRAPNO,
  X86_64_REG_OLDMASK,
  X86_64_REG_CR2,

  X86_64_REG_SP = X86_64_REG_RSP,
  X86_64_REG_PC = X86_64_REG_RIP,
};

class Regs {
 public:
  Regs(uint16_t pc_reg, uint16_t sp_reg) : pc_reg_(pc_reg), sp_reg_(sp_reg) {}
  virtual ~Regs() = default;

  uint16_t pc_reg() { return pc_reg_; }
  uint16_t sp_reg() { return sp_reg_; }

  virtual uint64_t pc() = 0;
  virtual uint64_t sp() = 0;

 protected:
  uint16_t pc_reg_;
  uint16_t sp_reg_;
};

template <typename AddressType>
class RegsTmpl : public Regs {
 public:
  RegsTmpl(uint16_t pc_reg, uint16_t sp_reg, void* reg_mem)
      : Regs(pc_reg, sp_reg), regs_(reinterpret_cast<AddressType*>(reg_mem)) {}
  virtual ~RegsTmpl() = default;

  uint64_t pc() override { return regs_[pc_reg_]; }
  uint64_t sp() override { return regs_[sp_reg_]; }

  inline AddressType value(uint16_t reg) { return regs_[reg]; }
  inline AddressType* addr(uint16_t reg) { return &regs_[reg]; }
  inline void set(uint16_t reg, AddressType value) { regs_[reg] = value; }

 private:
  AddressType* regs_;
};

class Regs32 : public RegsTmpl<uint32_t> {
 public:
  Regs32(uint16_t pc_reg, uint16_t sp_reg, void* reg_mem) : RegsTmpl(pc_reg, sp_reg, reg_mem) {}
  virtual ~Regs32() = default;
};

class Regs64 : public RegsTmpl<uint64_t> {
 public:
  Regs64(uint16_t pc_reg, uint16_t sp_reg, void* reg_mem) : RegsTmpl(pc_reg, sp_reg, reg_mem) {}
  virtual ~Regs64() = default;
};

#endif  // _LIBANDROID_UNWIND_REGS_H
