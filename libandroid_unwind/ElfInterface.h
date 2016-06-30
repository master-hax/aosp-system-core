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
#include <string>
#include <unordered_map>
#include <vector>

#include "ElfArmInterface.h"
#include "Memory.h"

struct LoadInfo {
  umaxptr_t offset;
  umaxptr_t table_offset;
  size_t table_size;
};

class ElfInterface {
 public:
  ElfInterface(Memory* memory) : memory_(memory) { }
  virtual ~ElfInterface() = default;

  virtual bool ProcessProgramHeaders() = 0;

  virtual bool ProcessDynamicHeaders() = 0;

  virtual std::string ReadSoname() = 0;

  const std::unordered_map<umaxptr_t, LoadInfo>& pt_loads() { return pt_loads_; }

  umaxptr_t dynamic_offset() { return dynamic_offset_; }
  umaxptr_t dynamic_size() { return dynamic_size_; }
  umaxptr_t eh_frame_offset() { return eh_frame_offset_; }
  umaxptr_t strtab_offset() { return strtab_offset_; }
  size_t soname_offset() { return soname_offset_; }

 protected:
  Memory* memory_;
  std::unordered_map<umaxptr_t, LoadInfo> pt_loads_;

  umaxptr_t eh_frame_offset_ = 0;

  umaxptr_t dynamic_offset_ = 0;
  size_t dynamic_size_ = 0;

  umaxptr_t strtab_offset_ = 0;
  umaxptr_t soname_offset_ = 0;
};

template <typename EhdrType, typename PhdrType, typename DynType>
class ElfTemplateInterface : public ElfInterface {
 public:
  ElfTemplateInterface(Memory* memory) : ElfInterface(memory) { }
  virtual ~ElfTemplateInterface() = default;

  bool ProcessProgramHeaders() override {
    program_headers_processed_ = true;

    umaxptr_t offset = 0;
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
        if (!memory_->Read(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
          return false;
        }
        eh_frame_offset_ = phdr.p_offset;
        break;

      case PT_DYNAMIC:
        if (!memory_->Read(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
          return false;
        }
        dynamic_offset_ = phdr.p_offset;
        if (!memory_->Read(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
          return false;
        }
        dynamic_size_ = phdr.p_memsz;
        break;
      }
    }
    return true;
  }

  bool ProcessDynamicHeaders() override {
    dynamic_headers_processed_ = true;
    if (!program_headers_processed_) {
      return false;
    }

    DynType dyn;
    umaxptr_t offset = dynamic_offset_;
    umaxptr_t max_offset = offset + dynamic_size_;
    for (umaxptr_t offset = dynamic_offset_; offset < max_offset; offset += sizeof(DynType)) {
      if (!memory_->Read(offset, &dyn, sizeof(dyn))) {
        return false;
      }

      if (dyn.d_tag == DT_STRTAB) {
        strtab_offset_ = dyn.d_un.d_ptr;
      } else if (dyn.d_tag == DT_SONAME) {
        soname_offset_ = dyn.d_un.d_val;
      } else if (dyn.d_tag == DT_NULL) {
        break;
      }
    }
    return true;
  }

  std::string ReadSoname() override {
    if (!dynamic_headers_processed_) {
      return "";
    }

    std::vector<char> soname_raw(4097);
    char* data = soname_raw.data();
    umaxptr_t offset = strtab_offset_ + soname_offset_;
    for (size_t i = 0; i < soname_raw.size() - 1; i++) {
      if (!memory_->Read(offset + i, &data[i], 1)) {
        return "";
      }
      if (data[i] == '\0') {
        return data;
      }
    }
    data[soname_raw.size() - 1] = '\0';
    return data;
  }

 private:
  virtual bool HandleType(umaxptr_t, const PhdrType&) {
    return false;
  }

  bool program_headers_processed_ = false;

  bool dynamic_headers_processed_ = false;
};

class ElfInterface32 : public ElfTemplateInterface<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn> {
 public:
  ElfInterface32(Memory* memory) : ElfTemplateInterface(memory) { }
  virtual ~ElfInterface32() = default;

  ElfArmInterface* arm() { return arm_.get(); }

 private:
  bool HandleType(umaxptr_t offset, const Elf32_Phdr& phdr) override;

  std::unique_ptr<ElfArmInterface> arm_;
};

class ElfInterface64 : public ElfTemplateInterface<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn> {
 public:
  ElfInterface64(Memory* memory) : ElfTemplateInterface(memory) { }
  virtual ~ElfInterface64() = default;
};

#endif  // _LIBANDROID_UNWIND_ELFINTERFACE_H
