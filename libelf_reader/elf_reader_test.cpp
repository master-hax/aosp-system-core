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

#include <elf_reader/elf_reader.h>

#include <gtest/gtest.h>

using namespace android::libelf_reader;

struct ElfData {
  uint64_t min_vaddr;
  uint64_t text_vaddr;
  uint64_t text_size;
  uint64_t interp_vaddr;
};

// Info of testdata/elf32
static ElfData elf32_data = {
    .min_vaddr = 0,
    .text_vaddr = 0xacc,
    .text_size = 0x201c,
    .interp_vaddr = 0x154,
};

// Info of testdata/elf64
static ElfData elf64_data = {
    .min_vaddr = 0,
    .text_vaddr = 0xba0,
    .text_size = 0xfec,
    .interp_vaddr = 0x238,
};

template <typename ElfTypes>
void VerifyElf(ElfReaderImpl<ElfTypes>* elf, const ElfData& elf_data) {
  auto header = elf->ReadHeader();
  ASSERT_TRUE(header != nullptr);
  auto sec_headers = elf->ReadSectionHeaders();
  ASSERT_TRUE(sec_headers != nullptr);
  auto program_headers = elf->ReadProgramHeaders();
  ASSERT_TRUE(program_headers != nullptr);
  uint64_t min_vaddr;
  ASSERT_TRUE(elf->GetMinExecutableVaddr(&min_vaddr));
  ASSERT_EQ(elf_data.min_vaddr, min_vaddr);

  const typename ElfTypes::Shdr* text_sec = nullptr;
  for (auto& sec : *sec_headers) {
    const char* name = elf->GetSectionName(sec);
    if (strcmp(name, ".text") == 0) {
      text_sec = &sec;
      break;
    }
  }
  ASSERT_TRUE(text_sec != nullptr);
  ASSERT_EQ(elf_data.text_vaddr, text_sec->sh_addr);
  ASSERT_EQ(elf_data.text_size, text_sec->sh_size);
  SectionData data = elf->ReadSectionData(*text_sec);
  ASSERT_TRUE(data.data != nullptr);
  ASSERT_EQ(elf_data.text_size, data.size);

  std::string data_in_string;
  ASSERT_TRUE(elf->ReadSectionData(".text", &data_in_string));
  ASSERT_EQ(elf_data.text_size, data_in_string.size());
  ASSERT_EQ(0, memcmp(&data_in_string[0], data.data, data.size));

  std::vector<uint8_t> data_in_vector;
  ASSERT_TRUE(elf->ReadSectionData(".text", &data_in_vector));
  ASSERT_EQ(elf_data.text_size, data_in_vector.size());
  ASSERT_EQ(0, memcmp(&data_in_vector[0], data.data, data.size));

  const typename ElfTypes::Phdr* interp_ph = nullptr;
  for (auto& ph : *program_headers) {
    if (ph.p_type == PT_INTERP) {
      interp_ph = &ph;
      break;
    }
  }
  ASSERT_TRUE(interp_ph != nullptr);
  ASSERT_EQ(elf_data.interp_vaddr, interp_ph->p_vaddr);
}

TEST(elf_reader, read_elf32) {
  std::string error_msg;
  std::unique_ptr<ElfReader> reader = ElfReader::OpenFile("testdata/elf32", 0, &error_msg);
  ASSERT_TRUE(reader != nullptr) << error_msg;
  ElfReader32* elf = reader->GetImpl32();
  ASSERT_TRUE(elf != nullptr);
  VerifyElf(elf, elf32_data);
}

TEST(elf_reader, read_elf64) {
  std::string error_msg;
  std::unique_ptr<ElfReader> reader = ElfReader::OpenFile("testdata/elf64", 0, &error_msg);
  ASSERT_TRUE(reader != nullptr) << error_msg;
  ElfReader64* elf = reader->GetImpl64();
  ASSERT_TRUE(elf != nullptr);
  VerifyElf(elf, elf64_data);
}
