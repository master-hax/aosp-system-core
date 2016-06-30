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

#include <memory>

#include <gtest/gtest.h>

#include "ElfInterface.h"

#include "LogFake.h"
#include "MemoryFake.h"

#if !defined(PT_ARM_EXIDX)
#define PT_ARM_EXIDX 0x70000001
#endif

#if !defined(EM_AARCH64)
#define EM_AARCH64 183
#endif

class ElfInterfaceTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
    memory_.Clear();
  }

  void SetMemory(uint64_t offset, void* memory, size_t length) {
    if ((length % sizeof(uint32_t)) != 0) {
      printf("Length %zu is not a multiple of %zu", length, sizeof(uint32_t));
      abort();
    }
    uint32_t* data = reinterpret_cast<uint32_t*>(memory);
    for (size_t i = 0; i < length / sizeof(uint32_t); i++) {
      memory_.SetData(offset + i * 4, data[i]);
    }
  }

  template<typename Ehdr, typename Phdr>
  void SinglePtLoad();

  template<typename Ehdr, typename Phdr>
  void MultipleExecutablePtLoads();

  template<typename Ehdr, typename Phdr>
  void MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr();

  template <typename Ehdr, typename Phdr>
  void NonExecutablePtLoads();

  template <typename Ehdr, typename Phdr>
  void ManyPhdrs();

  MemoryFake memory_;
};

template<typename Ehdr, typename Phdr>
void ElfInterfaceTest::SinglePtLoad() {
  std::unique_ptr<ElfInterface> elf(new ElfTemplateInterface<Ehdr, Phdr>(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Phdr);
  SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  SetMemory(0x100, &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->ProcessProgramHeaders());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(1U, pt_loads.size());
  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_single_pt_load) {
  SinglePtLoad<Elf32_Ehdr, Elf32_Phdr>();
}

TEST_F(ElfInterfaceTest, elf64_single_pt_load) {
  SinglePtLoad<Elf64_Ehdr, Elf64_Phdr>();
}

template <typename Ehdr, typename Phdr>
void ElfInterfaceTest::MultipleExecutablePtLoads() {
  std::unique_ptr<ElfInterface> elf(new ElfTemplateInterface<Ehdr, Phdr>(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 3;
  ehdr.e_phentsize = sizeof(Phdr);
  SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  SetMemory(0x100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x1000;
  phdr.p_vaddr = 0x2001;
  phdr.p_memsz = 0x10001;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1001;
  SetMemory(0x100 + sizeof(phdr), &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x2000;
  phdr.p_vaddr = 0x2002;
  phdr.p_memsz = 0x10002;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1002;
  SetMemory(0x100 + 2 * sizeof(phdr), &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->ProcessProgramHeaders());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(3U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);

  load_data = pt_loads.at(0x1000);
  ASSERT_EQ(0x1000U, load_data.offset);
  ASSERT_EQ(0x2001U, load_data.table_offset);
  ASSERT_EQ(0x10001U, load_data.table_size);

  load_data = pt_loads.at(0x2000);
  ASSERT_EQ(0x2000U, load_data.offset);
  ASSERT_EQ(0x2002U, load_data.table_offset);
  ASSERT_EQ(0x10002U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_multiple_executable_pt_loads) {
  MultipleExecutablePtLoads<Elf32_Ehdr, Elf32_Phdr>();
}

TEST_F(ElfInterfaceTest, elf64_multiple_executable_pt_loads) {
  MultipleExecutablePtLoads<Elf64_Ehdr, Elf64_Phdr>();
}

template<typename Ehdr, typename Phdr>
void ElfInterfaceTest::MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr() {
  std::unique_ptr<ElfInterface> elf(new ElfTemplateInterface<Ehdr, Phdr>(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 3;
  ehdr.e_phentsize = sizeof(Phdr) + 100;
  SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  SetMemory(0x100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x1000;
  phdr.p_vaddr = 0x2001;
  phdr.p_memsz = 0x10001;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1001;
  SetMemory(0x100 + sizeof(phdr) + 100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x2000;
  phdr.p_vaddr = 0x2002;
  phdr.p_memsz = 0x10002;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1002;
  SetMemory(0x100 + 2 * (sizeof(phdr) + 100), &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->ProcessProgramHeaders());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(3U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);

  load_data = pt_loads.at(0x1000);
  ASSERT_EQ(0x1000U, load_data.offset);
  ASSERT_EQ(0x2001U, load_data.table_offset);
  ASSERT_EQ(0x10001U, load_data.table_size);

  load_data = pt_loads.at(0x2000);
  ASSERT_EQ(0x2000U, load_data.offset);
  ASSERT_EQ(0x2002U, load_data.table_offset);
  ASSERT_EQ(0x10002U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_multiple_executable_pt_loads_increments_not_size_of_phdr) {
  MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr<Elf32_Ehdr, Elf32_Phdr>();
}

TEST_F(ElfInterfaceTest, elf64_multiple_executable_pt_loads_increments_not_size_of_phdr) {
  MultipleExecutablePtLoadsIncrementsNotSizeOfPhdr<Elf64_Ehdr, Elf64_Phdr>();
}

template <typename Ehdr, typename Phdr>
void ElfInterfaceTest::NonExecutablePtLoads() {
  std::unique_ptr<ElfInterface> elf(new ElfTemplateInterface<Ehdr, Phdr>(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 3;
  ehdr.e_phentsize = sizeof(Phdr);
  SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R;
  phdr.p_align = 0x1000;
  SetMemory(0x100, &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x1000;
  phdr.p_vaddr = 0x2001;
  phdr.p_memsz = 0x10001;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1001;
  SetMemory(0x100 + sizeof(phdr), &phdr, sizeof(phdr));

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_offset = 0x2000;
  phdr.p_vaddr = 0x2002;
  phdr.p_memsz = 0x10002;
  phdr.p_flags = PF_R;
  phdr.p_align = 0x1002;
  SetMemory(0x100 + 2 * sizeof(phdr), &phdr, sizeof(phdr));

  ASSERT_TRUE(elf->ProcessProgramHeaders());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(1U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0x1000);
  ASSERT_EQ(0x1000U, load_data.offset);
  ASSERT_EQ(0x2001U, load_data.table_offset);
  ASSERT_EQ(0x10001U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_non_executable_pt_loads) {
  NonExecutablePtLoads<Elf32_Ehdr, Elf32_Phdr>();
}

TEST_F(ElfInterfaceTest, elf64_non_executable_pt_loads) {
  NonExecutablePtLoads<Elf64_Ehdr, Elf64_Phdr>();
}

template <typename Ehdr, typename Phdr>
void ElfInterfaceTest::ManyPhdrs() {
  std::unique_ptr<ElfInterface> elf(new ElfTemplateInterface<Ehdr, Phdr>(&memory_));

  Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 7;
  ehdr.e_phentsize = sizeof(Phdr);
  SetMemory(0, &ehdr, sizeof(ehdr));

  Phdr phdr;
  uint64_t phdr_offset = 0x100;

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_LOAD;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0x10000;
  phdr.p_flags = PF_R | PF_X;
  phdr.p_align = 0x1000;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_GNU_EH_FRAME;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_DYNAMIC;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_INTERP;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_NOTE;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_SHLIB;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_GNU_EH_FRAME;
  SetMemory(phdr_offset, &phdr, sizeof(phdr));
  phdr_offset += sizeof(phdr);

  ASSERT_TRUE(elf->ProcessProgramHeaders());

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads = elf->pt_loads();
  ASSERT_EQ(1U, pt_loads.size());

  LoadInfo load_data = pt_loads.at(0);
  ASSERT_EQ(0U, load_data.offset);
  ASSERT_EQ(0x2000U, load_data.table_offset);
  ASSERT_EQ(0x10000U, load_data.table_size);
}

TEST_F(ElfInterfaceTest, elf32_many_phdrs) {
  ElfInterfaceTest::ManyPhdrs<Elf32_Ehdr, Elf32_Phdr>();
}

TEST_F(ElfInterfaceTest, elf64_many_phdrs) {
  ElfInterfaceTest::ManyPhdrs<Elf64_Ehdr, Elf64_Phdr>();
}

TEST_F(ElfInterfaceTest, elf32_arm) {
  ElfInterface32 elf32(&memory_);

  Elf32_Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_phoff = 0x100;
  ehdr.e_phnum = 1;
  ehdr.e_phentsize = sizeof(Elf32_Phdr);
  SetMemory(0, &ehdr, sizeof(ehdr));

  Elf32_Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type = PT_ARM_EXIDX;
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 16;
  SetMemory(0x100, &phdr, sizeof(phdr));

  // Add arm exidx entries.
  memory_.SetData(0x2000, 0x1000);
  memory_.SetData(0x2008, 0x1000);

  ASSERT_TRUE(elf32.ProcessProgramHeaders());
  ElfArmInterface* arm = elf32.arm();
  ASSERT_TRUE(arm != nullptr);

  std::vector<arm_ptr_t> entries;
  for (auto addr : *arm) {
    entries.push_back(addr);
  }
  ASSERT_EQ(2U, entries.size());
  ASSERT_EQ(0x3000U, entries[0]);
  ASSERT_EQ(0x3008U, entries[1]);
}
