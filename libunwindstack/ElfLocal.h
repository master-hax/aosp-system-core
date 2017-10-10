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

#ifndef _LIBUNWINDSTACK_ELF_LOCAL_H
#define _LIBUNWINDSTACK_ELF_LOCAL_H

#include <stdint.h>

#include <string>

#include <unwindstack/Elf.h>

namespace unwindstack {

// Forward declaration.
class Memory;
class Regs;

class ElfLocal : public Elf {
 public:
  ElfLocal(Memory* memory) : Elf(memory) { valid_ = true; }
  virtual ~ElfLocal() = default;

  bool GetFunctionName(uint64_t addr, std::string* name, uint64_t* func_offset) override;

  bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory, bool* finished) override;

  bool Init(uint64_t phoff, size_t phnum);

 protected:
  bool full_init_ = false;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_ELF_LOCAL_H
