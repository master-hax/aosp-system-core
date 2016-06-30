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
#include "Machine.h"
#include "Memory.h"
#include "Regs.h"
#include "Symbols.h"

struct LoadInfo {
  uint64_t offset;
  uint64_t table_offset;
  size_t table_size;
};

enum : uint8_t {
  SONAME_UNKNOWN = 0,
  SONAME_VALID,
  SONAME_INVALID,
};

class ElfInterfaceBase {
 public:
  ElfInterfaceBase(Memory* memory) : memory_(memory) {}
  virtual ~ElfInterfaceBase() = default;

  virtual bool Process() = 0;

  virtual bool GetSoname(std::string* name) = 0;

  virtual bool GetFunctionName(uint64_t addr, std::string* name) = 0;

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

  uint64_t dynamic_offset_;
  uint64_t dynamic_size_;
  uint64_t eh_frame_offset_;
  uint64_t eh_frame_size_;

  uint8_t soname_type_ = SONAME_UNKNOWN;
  std::string soname_;

  void (*dwarf_init_loc_func_)(dwarf_loc_regs_t*) = nullptr;

  std::unique_ptr<DwarfBase> dwarf_eh_frame_;
  std::unique_ptr<DwarfBase> dwarf_debug_frame_;
  std::unique_ptr<DwarfBase> dwarf_compressed_frame_;
};

template <typename EhdrType, typename PhdrType, typename DynType, typename ShdrType, typename SymType>
class ElfInterface : public ElfInterfaceBase {
 public:
  ElfInterface(Memory* memory) : ElfInterfaceBase(memory) {
    ehdr_.e_phoff = 0;
  }
  virtual ~ElfInterface() {
    for (auto symbol : symbols_) {
      delete symbol;
    }
  }

  bool Process() override {
    if (!ReadEhdr()) {
      return false;
    }
    if (!ProcessProgramHeaders()) {
      return false;
    }
    return ProcessSectionHeaders();
  }

  bool ProcessProgramHeaders() {
    uint64_t offset = ehdr_.e_phoff;
    for (size_t i = 0; i < ehdr_.e_phnum; i++, offset += ehdr_.e_phentsize) {
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

  bool ProcessSectionHeaders() {
    uint64_t offset = ehdr_.e_shoff;
    for (size_t i = 0; i < ehdr_.e_shnum; i++, offset += ehdr_.e_shentsize) {
      ShdrType shdr;
      if (!memory_->Read(offset, &shdr, &shdr.sh_type, sizeof(shdr.sh_type))) {
        return false;
      }

      if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
        if (!memory_->Read(offset, &shdr, sizeof(shdr))) {
          return false;
        }
        // Need to go get the information about the section that contains
        // the string terminated names.
        ShdrType str_shdr;
        if (shdr.sh_link >= ehdr_.e_shnum) {
          return false;
        }
        uint64_t str_offset = ehdr_.e_shoff + shdr.sh_link * ehdr_.e_shentsize;
        if (!memory_->Read(str_offset, &str_shdr, &str_shdr.sh_type, sizeof(str_shdr.sh_type))) {
          return false;
        }
        if (str_shdr.sh_type != SHT_STRTAB) {
          return false;
        }
        if (!memory_->Read(str_offset, &str_shdr, &str_shdr.sh_offset,
                           sizeof(str_shdr.sh_offset))) {
          return false;
        }
        if (!memory_->Read(str_offset, &str_shdr, &str_shdr.sh_size,
                           sizeof(str_shdr.sh_size))) {
          return false;
        }
        symbols_.push_back(new Symbols<SymType>(shdr.sh_offset, shdr.sh_size, shdr.sh_entsize,
                                                str_shdr.sh_offset, str_shdr.sh_size));
      }
    }
    return true;
  }

  bool GetSoname(std::string* soname) override {
    if (soname_type_ == SONAME_INVALID) {
      return false;
    }
    if (soname_type_ == SONAME_VALID) {
      *soname = soname_;
      return true;
    }

    soname_type_ = SONAME_INVALID;
    if (ehdr_.e_phoff == 0 && !ReadEhdr()) {
      return false;
    }

    uint64_t soname_offset = 0;
    uint64_t strtab_offset = 0;
    uint64_t strtab_size = 0;

    // Find the soname location from the dynamic headers section.
    DynType dyn;
    uint64_t offset = dynamic_offset_;
    uint64_t max_offset = offset + dynamic_size_;
    for (uint64_t offset = dynamic_offset_; offset < max_offset; offset += sizeof(DynType)) {
      if (!memory_->Read(offset, &dyn, sizeof(dyn))) {
        return false;
      }

      if (dyn.d_tag == DT_STRTAB) {
        strtab_offset = dyn.d_un.d_ptr;
      } else if (dyn.d_tag == DT_STRSZ) {
        strtab_size = dyn.d_un.d_val;
      } else if (dyn.d_tag == DT_SONAME) {
        soname_offset = dyn.d_un.d_val;
      } else if (dyn.d_tag == DT_NULL) {
        break;
      }
    }

    soname_offset += strtab_offset;
    if (soname_offset >= strtab_offset + strtab_size) {
      return false;
    }
    if (!memory_->ReadString(soname_offset, &soname_)) {
      return false;
    }
    soname_type_ = SONAME_VALID;
    *soname = soname_;
    return true;
  }

  bool GetFunctionName(uint64_t addr, std::string* name) override {
    if (symbols_.empty()) {
      return false;
    }

    for (const auto symbol : symbols_) {
      if (symbol->GetName(addr, load_bias_, memory_, name)) {
        return true;
      }
    }
    return false;
  }

 private:
  virtual bool HandleType(uint64_t, const PhdrType&) {
    return false;
  }

  bool ReadEhdr() {
    return memory_->Read(0, &ehdr_, sizeof(ehdr_));
  }

  EhdrType ehdr_;
  std::vector<Symbols<SymType>*> symbols_;
};

class ElfInterface32 : public ElfInterface<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn, Elf32_Shdr, Elf32_Sym> {
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

class ElfInterface64 : public ElfInterface<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, Elf64_Shdr, Elf64_Sym> {
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
