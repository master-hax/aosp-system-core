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

#ifndef _LIBANDROID_UNWIND_ELF_H
#define _LIBANDROID_UNWIND_ELF_H

#include <stddef.h>

#include <memory>
#include <string>

#include "ElfInterface.h"
#include "Memory.h"

#if !defined(EM_AARCH64)
#define EM_AARCH64 183
#endif

struct MapInfo;
class Regs;

class Elf {
 public:
  Elf(Memory* memory) : memory_(memory) {}
  virtual ~Elf() = default;

  bool Init();

  uint64_t GetRelPc(uint64_t pc, MapInfo* map_info);
  void AdjustPc(Regs* regs, MapInfo* map_info) {
    if (valid_) {
      interface_->AdjustPc(regs, map_info);
    }
  }

  bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory) {
    return valid_ && interface_->Step(rel_pc, regs, process_memory);
  }

  const std::string& GetSoname();

  bool valid() { return valid_; }

  uint32_t machine_type() { return machine_type_; }
  uint8_t class_type() { return class_type_; }

  Memory* memory() { return memory_.get(); }

  ElfInterfaceBase* GetInterface() { return interface_.get(); }

  void ClearCache() { if (interface_.get()) interface_->ClearCache(); }

 private:
  bool valid_ = false;
  std::unique_ptr<ElfInterfaceBase> interface_;
  std::string soname_;
  std::unique_ptr<Memory> memory_;
  uint32_t machine_type_;
  uint8_t class_type_;
};

#endif  // _LIBANDROID_UNWIND_ELF_H
