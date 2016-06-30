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

#include "Dwarf.h"
#include "DwarfEhFrame.h"
#include "MapInfo.h"
#include "Memory.h"
#include "Regs.h"

struct LoadInfo {
  uint64_t offset;
  uint64_t table_offset;
  size_t table_size;
};

class ElfInterfaceBase {
 public:
  ElfInterfaceBase(Memory* memory) : memory_(memory) {}
  virtual ~ElfInterfaceBase() = default;

  virtual bool ProcessProgramHeaders() = 0;

  virtual bool ProcessDynamicHeaders() = 0;

  virtual std::string ReadSoname() = 0;

  uint64_t GetRelPc(uint64_t pc, MapInfo* map_info) {
    return pc - map_info->start + load_bias_;
  }

  virtual void AdjustPc(Regs*, MapInfo*) {}

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads() { return pt_loads_; }
  uint64_t load_bias() { return load_bias_; }

  uint64_t dynamic_offset() { return dynamic_offset_; }
  uint64_t dynamic_size() { return dynamic_size_; }
  uint64_t eh_frame_offset() { return eh_frame_offset_; }
  uint64_t eh_frame_size() { return eh_frame_size_; }
  uint64_t strtab_offset() { return strtab_offset_; }
  size_t soname_offset() { return soname_offset_; }

  virtual void InitEhFrame() = 0;
  virtual bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory) = 0;

  template <typename AddressType>
  void ReadEhFrame() {
    // See http://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic.pdf
    // Section 10.6 for a description of the eh_frame data.
    if (eh_frame_offset_ == 0) {
      return;
    }
    std::unique_ptr<DwarfEhFrame<AddressType>> dwarf(new DwarfEhFrame<AddressType>(memory_, nullptr));
    if (!dwarf->Init(eh_frame_offset_)) {
      // If we have a failure, clear out the offset since this will never work.
      eh_frame_offset_ = 0;
      return;
    }

    dwarf_eh_frame_.reset(dwarf.release());
  }

  DwarfBase* GetDwarfEhFrame() { return dwarf_eh_frame_.get(); }
  DwarfBase* GetDwarfDebugFrame() { return dwarf_debug_frame_.get(); }
  DwarfBase* GetDwarfCompressedFrame() { return dwarf_compressed_frame_.get(); }

  virtual void ClearCache() { }
  void set_dwarf_init_loc_func(void (*func)(dwarf_loc_regs_t*)) { dwarf_init_loc_func_ = func; }

 protected:
  Memory* memory_;
  std::unordered_map<uint64_t, LoadInfo> pt_loads_;
  uint64_t load_bias_ = 0;

  uint64_t eh_frame_offset_ = 0;
  uint64_t eh_frame_size_ = 0;

  uint64_t dynamic_offset_ = 0;
  uint64_t dynamic_size_ = 0;

  uint64_t strtab_offset_ = 0;
  uint64_t soname_offset_ = 0;

  void (*dwarf_init_loc_func_)(dwarf_loc_regs_t*) = nullptr;

  std::unique_ptr<DwarfBase> dwarf_eh_frame_;
  std::unique_ptr<DwarfBase> dwarf_debug_frame_;
  std::unique_ptr<DwarfBase> dwarf_compressed_frame_;
};

template <typename EhdrType, typename PhdrType, typename DynType>
class ElfInterface : public ElfInterfaceBase {
 public:
  ElfInterface(Memory* memory) : ElfInterfaceBase(memory) {}
  virtual ~ElfInterface() = default;

  bool ProcessProgramHeaders() override {
    program_headers_processed_ = true;

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
        if (phdr.p_offset == 0) {
          load_bias_ = phdr.p_vaddr;
        }
        break;
      }

      case PT_GNU_EH_FRAME:
        if (!memory_->Read(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
          return false;
        }
        eh_frame_offset_ = phdr.p_offset;
        if (!memory_->Read(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
          return false;
        }
        eh_frame_size_ = phdr.p_memsz;
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
    uint64_t offset = dynamic_offset_;
    uint64_t max_offset = offset + dynamic_size_;
    for (uint64_t offset = dynamic_offset_; offset < max_offset; offset += sizeof(DynType)) {
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
    uint64_t offset = strtab_offset_ + soname_offset_;
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
  virtual bool HandleType(uint64_t, const PhdrType&) {
    return false;
  }

  bool program_headers_processed_ = false;

  bool dynamic_headers_processed_ = false;
};

class ElfInterface32 : public ElfInterface<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn> {
 public:
  ElfInterface32(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterface32() = default;

  void InitEhFrame() override { return ElfInterface::ReadEhFrame<uint32_t>(); }

  bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory) override {
    DwarfEhFrame<uint32_t>* eh_frame = reinterpret_cast<DwarfEhFrame<uint32_t>*>(dwarf_eh_frame_.get());
    if (eh_frame == nullptr) {
      return false;
    }

    uint64_t fde_offset;
    if (!eh_frame->GetFdeOffset(rel_pc, &fde_offset)) {
      return false;
    }
    DwarfCIE cie;
    DwarfFDE fde;
    if (!eh_frame->GetEntryData(fde_offset, &cie, &fde)) {
      return false;
    }

    // Now get the location information for this pc.
    dwarf_loc_regs_t loc_regs;

    // Init the location values.
    if (dwarf_init_loc_func_ != nullptr) {
      dwarf_init_loc_func_(&loc_regs);
    }
    if (!eh_frame->GetCfaLocationInfo(rel_pc, &cie, &fde, &loc_regs)) {
      return false;
    }

    // Now eval the actual registers.
    return eh_frame->Eval(process_memory, loc_regs, regs);
  }
};

class ElfInterfaceX86 : public ElfInterface32 {
 public:
  ElfInterfaceX86(Memory* memory) : ElfInterface32(memory) {}
  virtual ~ElfInterfaceX86() = default;

  void AdjustPc(Regs* regs, MapInfo*) {
    Regs32* regs32 = reinterpret_cast<Regs32*>(regs);
    uint32_t* pc = regs32->addr(X86_REG_PC);
    if (*pc != 0) {
      *pc -= 1;
    }
  }
};

class ElfInterface64 : public ElfInterface<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn> {
 public:
  ElfInterface64(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterface64() = default;

  void InitEhFrame() override { return ElfInterface::ReadEhFrame<uint64_t>(); }

  bool Step(uint64_t, Regs*, Memory*) override {
    return true;
  }
};

class ElfInterfaceX86_64 : public ElfInterface64 {
 public:
  ElfInterfaceX86_64(Memory* memory) : ElfInterface64(memory) {}
  virtual ~ElfInterfaceX86_64() = default;

  void AdjustPc(Regs* regs, MapInfo*) {
    Regs64* regs64 = reinterpret_cast<Regs64*>(regs);
    uint64_t* pc = regs64->addr(X86_64_REG_PC);
    if (*pc != 0) {
      *pc -= 1;
    }
  }
};

class ElfInterfaceArm64 : public ElfInterface64 {
 public:
  ElfInterfaceArm64(Memory* memory) : ElfInterface64(memory) {}
  virtual ~ElfInterfaceArm64() = default;

  void AdjustPc(Regs* regs, MapInfo*) {
    Regs64* regs64 = reinterpret_cast<Regs64*>(regs);
    uint64_t* pc = regs64->addr(ARM64_REG_PC);
    if (*pc != 0) {
      *pc -= 1;
    }
  }
};

#endif  // _LIBANDROID_UNWIND_ELFINTERFACE_H
