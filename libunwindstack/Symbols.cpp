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

#include <elf.h>
#include <stdint.h>

#include <algorithm>
#include <deque>
#include <string>
#include <vector>

#include <unwindstack/Memory.h>

#include "Check.h"
#include "Symbols.h"

namespace unwindstack {

Symbols::Symbols(uint64_t offset, uint64_t size, uint64_t entry_size, uint64_t str_offset,
                 uint64_t str_size)
    : offset_(offset),
      count_(entry_size != 0 ? size / entry_size : 0),
      entry_size_(entry_size),
      str_offset_(str_offset),
      str_end_(str_offset_ + str_size) {}

template <typename SymType>
static bool IsFunc(const SymType* entry) {
  return entry->st_shndx != SHN_UNDEF && ELF32_ST_TYPE(entry->st_info) == STT_FUNC;
}

// Binary search the symbol table to find function containing the given address.
// Without remap, the symbol table is assumed to be sorted and accessed directly.
// If the symbol table is not sorted this method mind fail but should not crash.
// When the indices are remapped, they are guaranteed to be sorted by address.
template <bool RemapIndices, typename SymType>
bool Symbols::BinarySearch(uint64_t addr, Memory* elf_memory, SymType* entry) {
  size_t first = 0;
  size_t last = RemapIndices ? remap_.size() : count_;
  while (first < last) {
    size_t current = first + (last - first) / 2;
    size_t remaped = RemapIndices ? remap_[current] : current;
    if (!elf_memory->ReadFully(offset_ + remaped * entry_size_, entry, sizeof(SymType))) {
      return false;
    }
    if (addr < entry->st_value) {
      last = current;
    } else if (addr < entry->st_value + entry->st_size) {
      return true;
    } else {
      first = current + 1;
    }
  }
  return false;
}

template <typename SymType>
bool Symbols::GetEntry(uint64_t addr, Memory* elf_memory, SymType* entry) {
  // Assume the symbol table is sorted. If it is not, this will gracefully fail.
  if (remap_.empty() && BinarySearch<false>(addr, elf_memory, entry) && IsFunc(entry)) {
    return true;
  }

  // Build remapping table, which allows us to access the symbols in sorted order.
  if (remap_.empty()) {
    std::vector<uint64_t> addrs;
    addrs.reserve(count_);
    for (uint32_t i = 0; i < count_; i++) {
      if (!elf_memory->ReadFully(offset_ + i * entry_size_, entry, sizeof(SymType))) {
        break;  // Stop processing, something looks like it is corrupted.
      }
      addrs.push_back(entry->st_value);
      if (IsFunc(entry)) {
        remap_.push_back(i);
      }
    }
    // Sort by address to make the remap list binary searchable.
    auto addr_lt = [&addrs](auto a, auto b) { return addrs[a] < addrs[b]; };
    std::stable_sort(remap_.begin(), remap_.end(), addr_lt);
    // Remove duplicate entries (methods de-duplicated by the linker).
    auto addr_eq = [&addrs](auto a, auto b) { return addrs[a] == addrs[b]; };
    remap_.erase(std::unique(remap_.begin(), remap_.end(), addr_eq), remap_.end());
  }

  // Binary search using the remapping table.
  if (BinarySearch<true>(addr, elf_memory, entry)) {
    CHECK(IsFunc(entry));
    return true;
  }

  return false;
}

template <typename SymType>
bool Symbols::GetName(uint64_t addr, Memory* elf_memory, std::string* name, uint64_t* func_offset) {
  // Lookup the address in the cache (which is keyed by end address).
  auto it = cache_.upper_bound(addr);  // it.first > addr
  bool found = (it != cache_.end()) && (addr >= it->first - it->second.size);

  // Otherwise find the entry in the symbol table and cache it.
  SymType entry;
  if (!found) {
    if (!GetEntry(addr, elf_memory, &entry)) {
      return false;
    }
    FuncInfo info{.size = entry.st_size, .name = entry.st_name};
    it = cache_.emplace(entry.st_value + entry.st_size, info).first;
  }

  *func_offset = addr - (it->first - it->second.size);
  uint64_t str = str_offset_ + it->second.name;
  return str < str_end_ && elf_memory->ReadString(str, name, str_end_ - str);
}

template <typename SymType>
bool Symbols::GetGlobal(Memory* elf_memory, const std::string& name, uint64_t* memory_address) {
  for (uint32_t i = 0; i < count_; i++) {
    SymType entry;
    if (!elf_memory->ReadFully(offset_ + i * entry_size_, &entry, sizeof(entry))) {
      return false;
    }

    if (entry.st_shndx != SHN_UNDEF && ELF32_ST_TYPE(entry.st_info) == STT_OBJECT &&
        ELF32_ST_BIND(entry.st_info) == STB_GLOBAL) {
      uint64_t str_offset = str_offset_ + entry.st_name;
      if (str_offset < str_end_) {
        std::string symbol;
        if (elf_memory->ReadString(str_offset, &symbol, str_end_ - str_offset) && symbol == name) {
          *memory_address = entry.st_value;
          return true;
        }
      }
    }
  }
  return false;
}

// Instantiate all of the needed template functions.
template bool Symbols::GetName<Elf32_Sym>(uint64_t, Memory*, std::string*, uint64_t*);
template bool Symbols::GetName<Elf64_Sym>(uint64_t, Memory*, std::string*, uint64_t*);

template bool Symbols::GetGlobal<Elf32_Sym>(Memory*, const std::string&, uint64_t*);
template bool Symbols::GetGlobal<Elf64_Sym>(Memory*, const std::string&, uint64_t*);
}  // namespace unwindstack
