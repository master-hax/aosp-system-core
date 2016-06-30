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

#include "DwarfStructs.h"
#include "Machine.h"

// Arm
void Arm::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (uint16_t i = ARM_REG_R0; i <= ARM_REG_R15; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { ARM_REG_SP, 0 } };
}

// Arm64
void Arm64::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (uint16_t i = ARM64_REG_R0; i <= ARM64_REG_PC; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { ARM64_REG_SP, 0 } };
}

// X86
void X86::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (uint16_t i = X86_REG_GS; i <= X86_REG_SS; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { X86_REG_SP, 0 } };
}

// X86_64
void X86_64::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (uint16_t i = X86_64_REG_R8; i <= X86_64_REG_CR2; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { X86_64_REG_SP, 0 } };
}
