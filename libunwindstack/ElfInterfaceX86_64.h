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

#ifndef _LIBUNWINDSTACK_ELF_INTERFACE_X86_64_H
#define _LIBUNWINDSTACK_ELF_INTERFACE_X86_64_H

#include <stdint.h>

#include <unwindstack/ElfInterface.h>

// Forward declarations.
class Memory;

namespace unwindstack {

class ElfInterfaceX86_64 : public ElfInterface64 {
 public:
  ElfInterfaceX86_64(Memory* memory) : ElfInterface64(memory) {}
  virtual ~ElfInterfaceX86_64() = default;

  bool Step(uint64_t pc, Regs* regs, Memory* process_memory) override;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_ELF_INTERFACE_X86_64_H
