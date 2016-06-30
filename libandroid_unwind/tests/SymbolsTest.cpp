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

#include <errno.h>
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <vector>

#include <android-base/test_utils.h>
#include <android-base/file.h>
#include <gtest/gtest.h>

#include "Memory.h"
#include "MemoryFake.h"
#include "Symbols.h"

#include "LogFake.h"

template <typename TypeParam>
class SymbolsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ResetLogs();
  }

  MemoryFake memory_;
};
TYPED_TEST_CASE_P(SymbolsTest);

TYPED_TEST_P(SymbolsTest, function_bounds_check) {
  Symbols<TypeParam> symbols(0x1000, sizeof(TypeParam), sizeof(TypeParam), 0x2000, 0x100);

  TypeParam sym;
  uint64_t offset = 0x1000;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x5000;
  sym.st_size = 0x10;
  sym.st_name = 0x40;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));

  std::string fake_name("fake_function");
  this->memory_.SetMemory(0x2040, fake_name.c_str(), fake_name.size() + 1);

  std::string name;
  ASSERT_TRUE(symbols.GetName(0x5000, 0, &this->memory_, &name));
  ASSERT_EQ("fake_function", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0x500f, 0, &this->memory_, &name));
  ASSERT_EQ("fake_function", name);

  // Check one before and one after the function.
  ASSERT_FALSE(symbols.GetName(0x4fff, 0, &this->memory_, &name));
  ASSERT_FALSE(symbols.GetName(0x5010, 0, &this->memory_, &name));
}

TYPED_TEST_P(SymbolsTest, no_symbol) {
  Symbols<TypeParam> symbols(0x1000, sizeof(TypeParam), sizeof(TypeParam), 0x2000, 0x100);

  TypeParam sym;
  uint64_t offset = 0x1000;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x5000;
  sym.st_size = 0x10;
  sym.st_name = 0x40;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));

  std::string fake_name("fake_function");
  this->memory_.SetMemory(0x2040, fake_name.c_str(), fake_name.size() + 1);

  // First verify that we can get the name.
  std::string name;
  ASSERT_TRUE(symbols.GetName(0x5000, 0, &this->memory_, &name));
  ASSERT_EQ("fake_function", name);

  // Now modify the info field so it's no longer a function.
  sym.st_info = 0;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  ASSERT_FALSE(symbols.GetName(0x5000, 0, &this->memory_, &name));

  // Set the function back, and set the shndx to UNDEF.
  sym.st_info = STT_FUNC;
  sym.st_shndx = SHN_UNDEF;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  ASSERT_FALSE(symbols.GetName(0x5000, 0, &this->memory_, &name));
}

TYPED_TEST_P(SymbolsTest, multiple_entries) {
  Symbols<TypeParam> symbols(0x1000, sizeof(TypeParam) * 3, sizeof(TypeParam), 0x2000, 0x500);

  TypeParam sym;
  uint64_t offset = 0x1000;
  std::string fake_name;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x5000;
  sym.st_size = 0x10;
  sym.st_name = 0x40;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  fake_name = "function_one";
  this->memory_.SetMemory(0x2040, fake_name.c_str(), fake_name.size() + 1);
  offset += sizeof(sym);

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x3004;
  sym.st_size = 0x200;
  sym.st_name = 0x100;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  fake_name = "function_two";
  this->memory_.SetMemory(0x2100, fake_name.c_str(), fake_name.size() + 1);
  offset += sizeof(sym);

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0xa010;
  sym.st_size = 0x20;
  sym.st_name = 0x230;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  fake_name = "function_three";
  this->memory_.SetMemory(0x2230, fake_name.c_str(), fake_name.size() + 1);

  std::string name;
  ASSERT_TRUE(symbols.GetName(0x3005, 0, &this->memory_, &name));
  ASSERT_EQ("function_two", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0x5004, 0, &this->memory_, &name));
  ASSERT_EQ("function_one", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0xa011, 0, &this->memory_, &name));
  ASSERT_EQ("function_three", name);

  // Reget some of the others to verify getting one function name doesn't
  // affect any of the next calls.
  name.clear();
  ASSERT_TRUE(symbols.GetName(0x5008, 0, &this->memory_, &name));
  ASSERT_EQ("function_one", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0x3008, 0, &this->memory_, &name));
  ASSERT_EQ("function_two", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0xa01a, 0, &this->memory_, &name));
  ASSERT_EQ("function_three", name);
}

TYPED_TEST_P(SymbolsTest, multiple_entries_nonstandard_size) {
  uint64_t entry_size = sizeof(TypeParam) + 5;
  Symbols<TypeParam> symbols(0x1000, entry_size * 3, entry_size, 0x2000, 0x500);

  TypeParam sym;
  uint64_t offset = 0x1000;
  std::string fake_name;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x5000;
  sym.st_size = 0x10;
  sym.st_name = 0x40;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  fake_name = "function_one";
  this->memory_.SetMemory(0x2040, fake_name.c_str(), fake_name.size() + 1);
  offset += entry_size;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x3004;
  sym.st_size = 0x200;
  sym.st_name = 0x100;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  fake_name = "function_two";
  this->memory_.SetMemory(0x2100, fake_name.c_str(), fake_name.size() + 1);
  offset += entry_size;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0xa010;
  sym.st_size = 0x20;
  sym.st_name = 0x230;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  fake_name = "function_three";
  this->memory_.SetMemory(0x2230, fake_name.c_str(), fake_name.size() + 1);

  std::string name;
  ASSERT_TRUE(symbols.GetName(0x3005, 0, &this->memory_, &name));
  ASSERT_EQ("function_two", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0x5004, 0, &this->memory_, &name));
  ASSERT_EQ("function_one", name);

  name.clear();
  ASSERT_TRUE(symbols.GetName(0xa011, 0, &this->memory_, &name));
  ASSERT_EQ("function_three", name);
}

TYPED_TEST_P(SymbolsTest, load_bias) {
  Symbols<TypeParam> symbols(0x1000, sizeof(TypeParam), sizeof(TypeParam), 0x2000, 0x100);

  TypeParam sym;
  uint64_t offset = 0x1000;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x5000;
  sym.st_size = 0x10;
  sym.st_name = 0x40;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));

  std::string fake_name("fake_function");
  this->memory_.SetMemory(0x2040, fake_name.c_str(), fake_name.size() + 1);

  // Set a non-zero load_bias that should be a valid function offset.
  std::string name;
  ASSERT_TRUE(symbols.GetName(0x6004, 0x1000, &this->memory_, &name));
  ASSERT_EQ("fake_function", name);

  // Set a flag that should cause the load_bias to be ignored.
  sym.st_shndx = SHN_ABS;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  ASSERT_FALSE(symbols.GetName(0x6004, 0x1000, &this->memory_, &name));
}

TYPED_TEST_P(SymbolsTest, symtab_value_out_of_bounds) {
  Symbols<TypeParam> symbols_end_at_100(0x1000, sizeof(TypeParam) * 2, sizeof(TypeParam),
                                        0x2000, 0x100);
  Symbols<TypeParam> symbols_end_at_200(0x1000, sizeof(TypeParam) * 2, sizeof(TypeParam),
                                        0x2000, 0x200);

  TypeParam sym;
  uint64_t offset = 0x1000;

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x5000;
  sym.st_size = 0x10;
  sym.st_name = 0x0fb;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));
  offset += sizeof(sym);

  memset(&sym, 0, sizeof(sym));
  sym.st_info = STT_FUNC;
  sym.st_value = 0x3000;
  sym.st_size = 0x10;
  sym.st_name = 0x100;
  sym.st_shndx = SHN_COMMON;
  this->memory_.SetMemory(offset, &sym, sizeof(sym));

  // Put the name across the end of the tab.
  std::string fake_name("fake_function");
  this->memory_.SetMemory(0x20fb, fake_name.c_str(), fake_name.size() + 1);

  std::string name;
  // Verify that we can get the function name properly for both entries.
  ASSERT_TRUE(symbols_end_at_200.GetName(0x5000, 0, &this->memory_, &name));
  ASSERT_EQ("fake_function", name);
  ASSERT_TRUE(symbols_end_at_200.GetName(0x3000, 0, &this->memory_, &name));
  ASSERT_EQ("function", name);

  // Now use the symbol table that ends at 0x100.
  ASSERT_FALSE(symbols_end_at_100.GetName(0x5000, 0, &this->memory_, &name));
  ASSERT_FALSE(symbols_end_at_100.GetName(0x3000, 0, &this->memory_, &name));
}

REGISTER_TYPED_TEST_CASE_P(SymbolsTest,
                           function_bounds_check,
                           no_symbol,
                           multiple_entries,
                           multiple_entries_nonstandard_size,
                           load_bias,
                           symtab_value_out_of_bounds);

typedef ::testing::Types<Elf32_Sym, Elf64_Sym> SymbolsTestTypes;
INSTANTIATE_TYPED_TEST_CASE_P(, SymbolsTest, SymbolsTestTypes);
