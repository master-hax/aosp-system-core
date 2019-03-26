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

#ifndef _LIBUNWINDSTACK_SYMBOLS_H
#define _LIBUNWINDSTACK_SYMBOLS_H

#include <stdint.h>

#include <deque>
#include <map>
#include <string>

namespace unwindstack {

// Forward declaration.
class Memory;

class Symbols {
  struct FuncInfo {
    uint64_t size;
    uint64_t name;
  };

 public:
  Symbols(uint64_t offset, uint64_t size, uint64_t entry_size, uint64_t str_offset,
          uint64_t str_size);
  virtual ~Symbols() = default;

  template <typename SymType>
  bool GetName(uint64_t addr, Memory* elf_memory, std::string* name, uint64_t* func_offset);

  template <typename SymType>
  bool GetGlobal(Memory* elf_memory, const std::string& name, uint64_t* memory_address);

  void ClearCache() {
    remap_.clear();
    cache_.clear();
  }

 private:
  template <bool UseIndex, typename SymType>
  bool BinarySearch(uint64_t addr, Memory* elf_memory, SymType* entry);

  template <typename SymType>
  bool GetEntry(uint64_t addr, Memory* elf_memory, SymType* entry);

  const uint64_t offset_;
  const uint64_t count_;
  const uint64_t entry_size_;
  const uint64_t str_offset_;
  const uint64_t str_end_;

  std::deque<uint32_t> remap_;  // Indices of function symbols sorted by their address.

  std::map<uint64_t, FuncInfo> cache_;  // Previously seen methods sorted by end address.
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_SYMBOLS_H
