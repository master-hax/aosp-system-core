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

class Regs {
 public:
  Regs(uint16_t pc_reg, uint16_t sp_reg, uint16_t total_regs)
      : pc_reg_(pc_reg), sp_reg_(sp_reg), total_regs_(total_regs) {}
  virtual ~Regs() = default;

  uint16_t pc_reg() { return pc_reg_; }
  uint16_t sp_reg() { return sp_reg_; }
  uint16_t total_regs() { return total_regs_; }

  virtual uint64_t pc() = 0;
  virtual uint64_t sp() = 0;

 protected:
  uint16_t pc_reg_;
  uint16_t sp_reg_;
  uint16_t total_regs_;
};

template <typename AddressType>
class RegsTmpl : public Regs {
 public:
  RegsTmpl(uint16_t pc_reg, uint16_t sp_reg, uint16_t total_regs, void* reg_mem)
      : Regs(pc_reg, sp_reg, total_regs), regs_(reinterpret_cast<AddressType*>(reg_mem)) {}
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
  Regs32(uint16_t pc_reg, uint16_t sp_reg, uint16_t total_regs, void* reg_mem)
      : RegsTmpl(pc_reg, sp_reg, total_regs, reg_mem) {}
  virtual ~Regs32() = default;
};

class Regs64 : public RegsTmpl<uint64_t> {
 public:
  Regs64(uint16_t pc_reg, uint16_t sp_reg, uint16_t total_regs, void* reg_mem)
      : RegsTmpl(pc_reg, sp_reg, total_regs, reg_mem) {}
  virtual ~Regs64() = default;
};

#endif  // _LIBANDROID_UNWIND_REGS_H
