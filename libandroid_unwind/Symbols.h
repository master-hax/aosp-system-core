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

#ifndef _LIBANDROID_UNWIND_SYMBOLS_H
#define _LIBANDROID_UNWIND_SYMBOLS_H

#include <elf.h>

#include <string>

#include "Memory.h"

template <typename SymType>
class Symbols {
 public:
  Symbols(uint64_t offset, uint64_t size, uint64_t entry_size, uint64_t str_offset, uint64_t str_size)
      : offset_(offset), entry_size_(entry_size), str_offset_(str_offset) {
    end_ = offset + size;
    str_end_ = str_offset_ + str_size;
  }
  virtual ~Symbols() = default;

  bool GetName(uint64_t addr, uint64_t load_bias, Memory* elf_memory, std::string* name) {
    SymType entry;
    uint64_t cur_offset = offset_;
    while (cur_offset + entry_size_ <= end_) {
      if (!elf_memory->Read(cur_offset, &entry, sizeof(entry))) {
        return false;
      }
      if (entry.st_shndx != SHN_UNDEF && ELF32_ST_TYPE(entry.st_info) == STT_FUNC) {
        // Treat st_value as virtual address.
        uint64_t start_offset = entry.st_value;
        if (entry.st_shndx != SHN_ABS) {
          start_offset += load_bias;
        }
        uint64_t end_offset = start_offset + entry.st_size;
        if (addr >= start_offset && addr < end_offset) {
          uint64_t offset = str_offset_ + entry.st_name;
          if (offset < str_end_) {
            return elf_memory->ReadString(offset, name, str_end_ - offset);
          }
          return false;
        }
      }
      cur_offset += entry_size_;
    }
    return false;
  }

 private:
  uint64_t offset_;
  uint64_t end_;
  uint64_t entry_size_;
  uint64_t str_offset_;
  uint64_t str_end_;
};

#endif  // _LIBANDROID_UNWIND_SYMBOLS_H
