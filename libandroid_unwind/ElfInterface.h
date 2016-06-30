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

struct LoadInfo {
  uint64_t offset;
  uint64_t table_offset;
  size_t table_size;
};

class ElfInterface {
 public:
  ElfInterface(Memory* memory) : memory_(memory) { }
  virtual ~ElfInterface() = default;

  virtual bool ProcessProgramHeaders() = 0;

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads() { return pt_loads_; }

 protected:
  Memory* memory_;
  std::unordered_map<uint64_t, LoadInfo> pt_loads_;
};

template <typename EhdrType, typename PhdrType>
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
    if (!memory_->Read(offset, &ehdr, &ehdr.e_phentsize, sizeof(ehdr.e_phentsize))) {
      return false;
    }

    offset += ehdr.e_phoff;
    for (size_t i = 0; i < ehdr.e_phnum; i++, offset += ehdr.e_phentsize) {
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

        if (!memory_->Read(offset, &phdr, &phdr.p_vaddr, sizeof(phdr.p_vaddr))) {
          return false;
        }
        if (!memory_->Read(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
          return false;
        }
        if (!memory_->Read(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
          return false;
        }
        pt_loads_[phdr.p_offset] = LoadInfo{phdr.p_offset, phdr.p_vaddr,
                                            static_cast<size_t>(phdr.p_memsz)};
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

  uint64_t eh_frame_offset_ = 0;
  uint64_t dynamic_offset_ = 0;
};

class ElfInterface32 : public ElfTemplateInterface<Elf32_Ehdr, Elf32_Phdr> {
 public:
  ElfInterface32(Memory* memory) : ElfTemplateInterface(memory) { }
  virtual ~ElfInterface32() = default;

  ElfArmInterface* arm() { return arm_.get(); }

 private:
  bool HandleType(uint64_t offset, const Elf32_Phdr& phdr) override;

  std::unique_ptr<ElfArmInterface> arm_;
};

#endif  // _LIBANDROID_UNWIND_ELFINTERFACE_H
