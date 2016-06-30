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

#ifndef _LIBANDROID_UNWIND_MACHINE_H
#define _LIBANDROID_UNWIND_MACHINE_H

#include "DwarfStructs.h"
#include "Regs.h"

class Arm {
 public:
  static void InitLocationRegs(dwarf_loc_regs_t*);

  static uint16_t PcReg() { return ARM_REG_PC; }
  static uint16_t SpReg() { return ARM_REG_SP; }

  static size_t RegSize() { return (ARM_REG_R15 + 1) * sizeof(uint32_t); }
};

class Arm64 {
 public:
  static void InitLocationRegs(dwarf_loc_regs_t*);

  static uint16_t PcReg() { return ARM64_REG_PC; }
  static uint16_t SpReg() { return ARM64_REG_SP; }

  static size_t RegSize() { return (ARM64_REG_PC + 1) * sizeof(uint32_t); }
};

class X86 {
 public:
  static void InitLocationRegs(dwarf_loc_regs_t*);

  static uint16_t PcReg() { return X86_REG_PC; }
  static uint16_t SpReg() { return X86_REG_SP; }

  static size_t RegSize() { return (X86_REG_SS + 1) * sizeof(uint32_t); }
};

class X86_64 {
 public:
  static void InitLocationRegs(dwarf_loc_regs_t*);

  static uint16_t PcReg() { return X86_64_REG_PC; }
  static uint16_t SpReg() { return X86_64_REG_SP; }

  static size_t RegSize() { return (X86_64_REG_CR2 + 1) * sizeof(uint32_t); }
};

#endif  // _LIBANDROID_UNWIND_MACHINE_H
