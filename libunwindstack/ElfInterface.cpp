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

#include <memory>
#include <string>

#include "DwarfEhFrame.h"
#include "DwarfSection.h"
#include "ElfInterface.h"
#include "Memory.h"
#include "Regs.h"
#include "Symbols.h"

ElfInterface::~ElfInterface() {
  for (auto symbol : symbols_) {
    delete symbol;
  }
}

template <typename AddressType>
void ElfInterface::ReadEhFrame() {
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

  eh_frame_.reset(dwarf.release());
}

template <typename EhdrType, typename PhdrType, typename ShdrType>
bool ElfInterface::ReadAllHeaders() {
  EhdrType ehdr;
  if (!memory_->Read(0, &ehdr, sizeof(ehdr))) {
    return false;
  }

  if (!ReadProgramHeaders<EhdrType, PhdrType>(ehdr)) {
    return false;
  }
  return ReadSectionHeaders<EhdrType, ShdrType>(ehdr);
}

template <typename EhdrType, typename PhdrType>
bool ElfInterface::ReadProgramHeaders(const EhdrType& ehdr) {
  uint64_t offset = ehdr.e_phoff;
  for (size_t i = 0; i < ehdr.e_phnum; i++, offset += ehdr.e_phentsize) {
    PhdrType phdr;
    if (!memory_->Read(offset, &phdr, &phdr.p_type, sizeof(phdr.p_type))) {
      return false;
    }

    if (HandleType(offset, phdr.p_type)) {
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

template <typename EhdrType, typename ShdrType>
bool ElfInterface::ReadSectionHeaders(const EhdrType& ehdr) {
  uint64_t offset = ehdr.e_shoff;
  for (size_t i = 0; i < ehdr.e_shnum; i++, offset += ehdr.e_shentsize) {
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
      if (shdr.sh_link >= ehdr.e_shnum) {
        return false;
      }
      uint64_t str_offset = ehdr.e_shoff + shdr.sh_link * ehdr.e_shentsize;
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
      symbols_.push_back(new Symbols(shdr.sh_offset, shdr.sh_size, shdr.sh_entsize,
                                     str_shdr.sh_offset, str_shdr.sh_size));
    }
  }
  return true;
}

template <typename DynType>
bool ElfInterface::GetSonameWithTemplate(std::string* soname) {
  if (soname_type_ == SONAME_INVALID) {
    return false;
  }
  if (soname_type_ == SONAME_VALID) {
    *soname = soname_;
    return true;
  }

  soname_type_ = SONAME_INVALID;

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

template <typename SymType>
bool ElfInterface::GetFunctionNameWithTemplate(uint64_t addr, std::string* name,
                                               uint64_t* func_offset) {
  if (symbols_.empty()) {
    return false;
  }

  for (const auto symbol : symbols_) {
    if (symbol->GetName<SymType>(addr, load_bias_, memory_, name, func_offset)) {
      return true;
    }
  }
  return false;
}

bool ElfInterface::Step(uint64_t pc, Regs* regs, Memory* process_memory) {
  DwarfSection* eh_frame = eh_frame_.get();
  if (eh_frame == nullptr) {
    return false;
  }

  // Need to subtract off the load_bias to get the correct pc.
  if (pc < load_bias_) {
    return false;
  }
  pc -= load_bias_;

  const DwarfFDE* fde = eh_frame->GetFDEFromPC(pc);
  if (fde == nullptr) {
    return false;
  }

  // Now get the location information for this pc.
  dwarf_loc_regs_t loc_regs;
  if (!eh_frame->GetCfaLocationInfo(pc, fde, &loc_regs)) {
    return false;
  }

  // Now eval the actual registers.
  return eh_frame->Eval(fde->cie, process_memory, loc_regs, regs);
}

// Instantiate all of the needed template functions.
template void ElfInterface::ReadEhFrame<uint32_t>();
template void ElfInterface::ReadEhFrame<uint64_t>();

template bool ElfInterface::ReadAllHeaders<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr>();
template bool ElfInterface::ReadAllHeaders<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr>();

template bool ElfInterface::ReadProgramHeaders<Elf32_Ehdr, Elf32_Phdr>(const Elf32_Ehdr&);
template bool ElfInterface::ReadProgramHeaders<Elf64_Ehdr, Elf64_Phdr>(const Elf64_Ehdr&);

template bool ElfInterface::ReadSectionHeaders<Elf32_Ehdr, Elf32_Shdr>(const Elf32_Ehdr&);
template bool ElfInterface::ReadSectionHeaders<Elf64_Ehdr, Elf64_Shdr>(const Elf64_Ehdr&);

template bool ElfInterface::GetSonameWithTemplate<Elf32_Dyn>(std::string*);
template bool ElfInterface::GetSonameWithTemplate<Elf64_Dyn>(std::string*);

template bool ElfInterface::GetFunctionNameWithTemplate<Elf32_Sym>(
    uint64_t, std::string*, uint64_t*);
template bool ElfInterface::GetFunctionNameWithTemplate<Elf64_Sym>(
    uint64_t, std::string*, uint64_t*);
