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
  for (size_t i = 0; i < 16; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 13, 0 } };
}

// Arm64
void Arm64::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (size_t i = 0; i < 32; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 31, 0 } };
}

// X86
void X86::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (size_t i = 0; i < 17; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 7, 0 } };
}

// X86_64
void X86_64::InitLocationRegs(dwarf_loc_regs_t* loc_regs) {
  for (size_t i = 0; i < 17; i++) {
    (*loc_regs)[i] = { .type = DWARF_LOCATION_SAME };
  }
  (*loc_regs)[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 15, 0 } };
}
