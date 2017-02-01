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

#include <elf.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <vector>

#include "Elf.h"
#include "ElfInterface.h"
#include "Machine.h"
#include "MapInfo.h"
#include "Regs.h"

RegsArm::RegsArm() : RegsTmpl<uint32_t>(ARM_REG_LAST, ARM_REG_SP) {
}

uint64_t RegsArm::GetRelPc(size_t frame_num, Elf* elf, const MapInfo* map_info) {
  uint64_t load_bias = elf->interface()->load_bias();
  uint64_t rel_pc = pc_ - map_info->start;
  if (frame_num == 0 || rel_pc < 5) {
    return rel_pc + load_bias;
  }

  if (rel_pc & 1) {
    // This is a thumb instruction, it could be 2 or 4 bytes.
    uint32_t value;
    if (rel_pc < 5 || !elf->memory()->Read(rel_pc - 5, &value, sizeof(value)) ||
        (value & 0xe000f000) != 0xe000f000) {
      return rel_pc + load_bias - 2;
    }
  }
  return rel_pc + load_bias - 4;
}

RegsArm64::RegsArm64() : RegsTmpl<uint64_t>(ARM64_REG_LAST, ARM64_REG_SP) {
}

uint64_t RegsArm64::GetRelPc(size_t frame_num, Elf* elf, const MapInfo* map_info) {
  uint64_t rel_pc = pc_ - map_info->start + elf->interface()->load_bias();
  if (frame_num == 0 || rel_pc < 4) {
    return rel_pc;
  }

  return rel_pc - 4;
}

RegsX86::RegsX86() : RegsTmpl<uint32_t>(X86_REG_LAST, X86_REG_SP) {
}

uint64_t RegsX86::GetRelPc(size_t frame_num, Elf* elf, const MapInfo* map_info) {
  uint64_t rel_pc = pc_ - map_info->start + elf->interface()->load_bias();
  if (frame_num == 0 || rel_pc == 0) {
    return rel_pc;
  }
  return rel_pc - 1;
}

RegsX86_64::RegsX86_64() : RegsTmpl<uint64_t>(X86_64_REG_LAST, X86_64_REG_SP) {
}

uint64_t RegsX86_64::GetRelPc(size_t frame_num, Elf* elf, const MapInfo* map_info) {
  uint64_t rel_pc = pc_ - map_info->start + elf->interface()->load_bias();
  if (frame_num == 0 || rel_pc == 0) {
    return rel_pc;
  }

  return rel_pc - 1;
}
