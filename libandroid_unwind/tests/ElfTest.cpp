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

#include <elf.h>

#include <gtest/gtest.h>

#include "Elf.h"

#include "LogFake.h"
#include "MemoryFake.h"

#if !defined(PT_ARM_EXIDX)
#define PT_ARM_EXIDX 0x70000001
#endif

#if !defined(EM_AARCH64)
#define EM_AARCH64 183
#endif

class ElfTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
  }

  template <typename Ehdr>
  void InitEhdr(Ehdr* ehdr) {
    memset(ehdr, 0, sizeof(Ehdr));
    memcpy(&ehdr->e_ident[0], ELFMAG, SELFMAG);
    if (sizeof(Ehdr) == sizeof(Elf32_Ehdr)) {
      ehdr->e_ident[EI_CLASS] = ELFCLASS32;
    } else {
      ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    }
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
  }

  void InitElf(Memory* memory, int type) {
    MemoryFake* memory_fake = reinterpret_cast<MemoryFake*>(memory);
    if (type == EM_ARM || type == EM_386) {
      Elf32_Ehdr ehdr;
      InitEhdr<Elf32_Ehdr>(&ehdr);
      ehdr.e_type = ET_DYN;
      ehdr.e_machine = type;
      ehdr.e_version = EV_CURRENT;
      ehdr.e_entry = 0;
      ehdr.e_phoff = 0x100;
      ehdr.e_shoff = 0;
      ehdr.e_flags = 0;
      ehdr.e_ehsize = sizeof(ehdr);
      ehdr.e_phentsize = sizeof(Elf32_Phdr);
      ehdr.e_phnum = 1;
      ehdr.e_shentsize = sizeof(Elf32_Shdr);
      ehdr.e_shnum = 0;
      ehdr.e_shstrndx = 0;
      if (type == EM_ARM) {
        ehdr.e_flags = 0x5000200;
        ehdr.e_phnum = 2;
      }
      SetMemory(memory_fake, 0, &ehdr, sizeof(ehdr));

      Elf32_Phdr phdr;
      memset(&phdr, 0, sizeof(phdr));
      phdr.p_type = PT_LOAD;
      phdr.p_offset = 0;
      phdr.p_vaddr = 0;
      phdr.p_paddr = 0;
      phdr.p_filesz = 0x10000;
      phdr.p_memsz = 0x10000;
      phdr.p_flags = PF_R | PF_X;
      phdr.p_align = 0x1000;
      SetMemory(memory_fake, 0x100, &phdr, sizeof(phdr));

      if (type == EM_ARM) {
        memset(&phdr, 0, sizeof(phdr));
        phdr.p_type = PT_ARM_EXIDX;
        phdr.p_offset = 0x30000;
        phdr.p_vaddr = 0x30000;
        phdr.p_paddr = 0x30000;
        phdr.p_filesz = 16;
        phdr.p_memsz = 16;
        phdr.p_flags = PF_R;
        phdr.p_align = 0x4;
        SetMemory(memory_fake, 0x100 + sizeof(phdr), &phdr, sizeof(phdr));
      }
    } else if (type == EM_AARCH64 || type == EM_X86_64) {
      Elf64_Ehdr ehdr;
      InitEhdr<Elf64_Ehdr>(&ehdr);
      ehdr.e_type = ET_DYN;
      ehdr.e_machine = type;
      ehdr.e_version = EV_CURRENT;
      ehdr.e_entry = 0;
      ehdr.e_phoff = 0x100;
      ehdr.e_shoff = 0;
      ehdr.e_flags = 0x5000200;
      ehdr.e_ehsize = sizeof(ehdr);
      ehdr.e_phentsize = sizeof(Elf64_Phdr);
      ehdr.e_phnum = 1;
      ehdr.e_shentsize = sizeof(Elf64_Shdr);
      ehdr.e_shnum = 0;
      ehdr.e_shstrndx = 0;
      SetMemory(memory_fake, 0, &ehdr, sizeof(ehdr));

      Elf64_Phdr phdr;
      memset(&phdr, 0, sizeof(phdr));
      phdr.p_type = PT_LOAD;
      phdr.p_offset = 0;
      phdr.p_vaddr = 0;
      phdr.p_paddr = 0;
      phdr.p_filesz = 0x10000;
      phdr.p_memsz = 0x10000;
      phdr.p_flags = PF_R | PF_X;
      phdr.p_align = 0x1000;
      SetMemory(memory_fake, 0x100, &phdr, sizeof(phdr));
    }
  }

  void SetMemory(MemoryFake* memory, uint64_t offset, void* dst, size_t length) {
    if ((length % sizeof(uint32_t)) != 0) {
      printf("Length %zu is not a multiple of %zu", length, sizeof(uint32_t));
      abort();
    }
    uint32_t* data = reinterpret_cast<uint32_t*>(dst);
    for (size_t i = 0; i < length / sizeof(uint32_t); i++) {
      memory->SetData(offset + i * 4, data[i]);
    }
  }
};

TEST_F(ElfTest, invalid_memory) {
  Elf elf(new MemoryFake);

  ASSERT_FALSE(elf.Init());
  ASSERT_FALSE(elf.valid());
}

TEST_F(ElfTest, elf_invalid) {
  Elf elf(new MemoryFake);
  InitElf(elf.memory(), EM_386);

  // Corrupt the ELF signature.
  reinterpret_cast<MemoryFake*>(elf.memory())->OverwriteData(0, 0x7f000000);

  ASSERT_FALSE(elf.Init());
  ASSERT_FALSE(elf.valid());
}

TEST_F(ElfTest, elf_arm) {
  Elf elf(new MemoryFake);
  InitElf(elf.memory(), EM_ARM);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
}

TEST_F(ElfTest, elf_x86) {
  Elf elf(new MemoryFake);
  InitElf(elf.memory(), EM_386);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
}

TEST_F(ElfTest, elf_arm64) {
  Elf elf(new MemoryFake);
  InitElf(elf.memory(), EM_AARCH64);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
}

TEST_F(ElfTest, elf_x86_64) {
  Elf elf(new MemoryFake);
  InitElf(elf.memory(), EM_X86_64);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
}
