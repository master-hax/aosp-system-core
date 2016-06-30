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

#include <unwindstack/ElfInterface.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

#include "ElfInterfaceX86_64.h"
#include "Machine.h"

namespace unwindstack {

bool ElfInterfaceX86_64::Step(uint64_t pc, Regs* regs_gen, Memory* process_memory) {
  if (ElfInterface64::Step(pc, regs_gen, process_memory)) {
    return true;
  }

  // All other options failed, see if we can guess the frame information.
  RegsX86_64* regs = reinterpret_cast<RegsX86_64*>(regs_gen);
  uint64_t rbp = (*regs)[X86_64_REG_RBP];
  if (rbp == 0) {
    return false;
  }
  if (rbp <= regs->sp() || (rbp - regs->sp()) > 0x4000) {
    // Unlikely that this can decode the frame data.
    return false;
  }
  if (!process_memory->Read(rbp + 8, &(*regs)[X86_64_REG_RIP], sizeof(uint64_t))) {
    return false;
  }
  (*regs)[X86_64_REG_RSP] += 16;
  regs->SetFromRaw();
  return true;
}

}  // namespace unwindstack
