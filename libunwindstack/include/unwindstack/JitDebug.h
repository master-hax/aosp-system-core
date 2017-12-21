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

#ifndef _LIBUNWINDSTACK_JIT_DEBUG_H
#define _LIBUNWINDSTACK_JIT_DEBUG_H

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

namespace unwindstack {

// Forward declarations.
class Elf;
class Maps;
class Memory;

class JitDebug {
 public:
  JitDebug(std::shared_ptr<Memory>& memory, std::vector<std::string>* search_libs = nullptr);
  virtual ~JitDebug();

  Elf* GetElf(Maps* maps, uint64_t pc);

 private:
  void Init(Maps* maps);

  std::shared_ptr<Memory> memory_;
  uint64_t entry_addr_ = 0;
  bool initialized_ = false;
  std::vector<Elf*> elf_list_;
  std::vector<std::string>* search_libs_;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_JIT_DEBUG_H
