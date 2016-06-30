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

#ifndef _LIBANDROID_UNWIND_ELFINTERFACE_H
#define _LIBANDROID_UNWIND_ELFINTERFACE_H

#include <elf.h>
#include <stdint.h>

#include <memory>
#include <unordered_map>

#include "ElfArmInterface.h"
#include "Memory.h"

class ElfInterface {
 public:
  ElfInterface(Memory* memory) : memory_(memory) { }
  virtual ~ElfInterface() = default;

  virtual bool ProcessProgramHeaders() = 0;

 protected:
  Memory* memory_;
};

struct LoadInfo32 {
  Elf32_Off offset;
  Elf32_Addr table_offset;
  Elf32_Word memsize;
};

struct LoadInfo64 {
  Elf64_Off offset;
  Elf64_Addr table_offset;
  Elf64_Xword memsize;
};

template <typename EhdrType, typename PhdrType, typename LoadType>
class ElfTemplateInterface : public ElfInterface {
 public:
  ElfTemplateInterface(Memory* memory) : ElfInterface(memory) { }
  virtual ~ElfTemplateInterface() = default;

  bool ProcessProgramHeaders() override {
    uint64_t offset = 0;
    EhdrType ehdr;
    if (!memory_->Read(offset, &ehdr, &ehdr.e_phoff, sizeof(ehdr.e_phoff))) {
      return false;
    }
    if (!memory_->Read(offset, &ehdr, &ehdr.e_phnum, sizeof(ehdr.e_phnum))) {
      return false;
    }

    offset += ehdr.e_phoff;
    for (size_t i = 0; i < ehdr.e_phnum; i++, offset += sizeof(PhdrType)) {
      PhdrType phdr;
      if (!memory_->Read(offset, &phdr, &phdr.p_type, sizeof(phdr.p_type))) {
        return false;
      }

      if (HandleType(offset, phdr)) {
        continue;
      }

      switch (phdr.p_type) {
      case PT_LOAD:
      {
        // Get the flags first, if this isn't an executable header, ignore it.
        if (!memory_->Read(offset, &phdr, &phdr.p_flags, sizeof(phdr.p_flags))) {
          return false;
        }
        if ((phdr.p_flags & PF_X) == 0) {
          continue;
        }

        LoadType load_info;
        uint64_t field_offset =
            reinterpret_cast<uintptr_t>(&phdr.p_vaddr) - reinterpret_cast<uintptr_t>(&phdr);
        if (!memory_->Read(offset + field_offset, &load_info.table_offset,
                           sizeof(load_info.table_offset))) {
          return false;
        }
        field_offset =
            reinterpret_cast<uintptr_t>(&phdr.p_offset) - reinterpret_cast<uintptr_t>(&phdr);
        if (!memory_->Read(offset + field_offset, &load_info.offset, sizeof(load_info.offset))) {
          return false;
        }
        field_offset =
            reinterpret_cast<uintptr_t>(&phdr.p_memsz) - reinterpret_cast<uintptr_t>(&phdr);
        if (!memory_->Read(offset + field_offset, &load_info.memsize, sizeof(load_info.memsize))) {
          return false;
        }
        pt_loads_[load_info.offset] = load_info;
        break;
      }

      case PT_GNU_EH_FRAME:
        eh_frame_offset_ = offset;
        break;

      case PT_DYNAMIC:
        dynamic_offset_ = offset;
        break;
      }
    }
    return true;
  }

 private:
  virtual bool HandleType(uint64_t, const PhdrType&) {
    return false;
  }

  std::unordered_map<uint64_t, LoadType> pt_loads_;
  uint64_t eh_frame_offset_ = 0;
  uint64_t dynamic_offset_ = 0;
};

class ElfInterface32 : public ElfTemplateInterface<Elf32_Ehdr, Elf32_Phdr, LoadInfo32> {
 public:
  ElfInterface32(Memory* memory) : ElfTemplateInterface(memory) { }
  virtual ~ElfInterface32() = default;

 private:
  bool HandleType(uint64_t offset, const Elf32_Phdr& phdr) override;

  std::unique_ptr<ElfArmInterface> arm_;
};

#endif  // _LIBANDROID_UNWIND_ELFINTERFACE_H
