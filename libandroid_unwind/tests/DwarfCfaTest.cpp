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

#include <stdint.h>

#include <memory>
#include <unordered_map>

#include <gtest/gtest.h>

#include "DwarfMemory.h"
#include "DwarfCfa.h"
#include "DwarfLocation.h"
#include "Log.h"

#include "LogFake.h"
#include "MemoryFake.h"

class DwarfCfaTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
    memory_.Clear();

    g_LoggingEnabled = true;
    g_LoggingIndentLevel = 0;
    g_LoggingOnly = false;

    dmem32_.reset(new DwarfMemory<uint32_t>(&memory_));
    dmem64_.reset(new DwarfMemory<uint64_t>(&memory_));

    cie_.cfa_instructions_offset = 0x1000;
    cie_.cfa_instructions_end = 0x1030;
    // These two values should be different to distinguish between
    // operations that deal with code versus data.
    cie_.code_alignment_factor = 4;
    cie_.data_alignment_factor = 8;

    fde_.cfa_instructions_offset = 0x2000;
    fde_.cfa_instructions_end = 0x2030;
    fde_.start_pc = 0xa0000;
  }

  template <typename AddressType>
  void cfa_illegal_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset,
                        size_t index);
  template <typename AddressType>
  void cfa_nop_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset);
  template <typename AddressType>
  void cfa_restore_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset);
  template <typename AddressType>
  void cfa_set_loc_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset);
  template <typename AddressType>
  void cfa_advance_loc1(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset);
  template <typename AddressType>
  void cfa_advance_loc2(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset);
  template <typename AddressType>
  void cfa_advance_loc4(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset);

  MemoryFake memory_;
  std::unique_ptr<DwarfMemory<uint32_t>> dmem32_;
  std::unique_ptr<DwarfMemory<uint64_t>> dmem64_;
  DwarfCIE cie_;
  DwarfFDE fde_;
};

template <typename AddressType>
void DwarfCfaTest::cfa_illegal_test(DwarfMemory<AddressType>* dmem, uint64_t pc,
                                    uint64_t offset, size_t index) {
  ResetLogs();
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_FALSE(cfa.Eval(pc, offset + index * 4, offset + 1 + index * 4));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, cfa.last_error());

  std::string expected = android::base::StringPrintf("4 unwind Raw Data: 0x%02zx\n", index);
  expected += "4 unwind Illegal\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_illegal) {
  for (size_t i = 0x17; i < 0x3f; i++) {
    if (i == 0x2e || i == 0x2f) {
      continue;
    }
    memory_.SetData(0x2000 + i * 4, i);
    cfa_illegal_test<uint32_t>(dmem32_.get(), 0xa0000, 0x2000, i);
    cfa_illegal_test<uint64_t>(dmem64_.get(), 0xa0000, 0x2000, i);
  }
}

template <typename AddressType>
void DwarfCfaTest::cfa_nop_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset) {
  memory_.SetData(0x2000, 0);
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_TRUE(cfa.Eval(pc, offset, offset + 1));

  std::string expected = "4 unwind Raw Data: 0x00\n"
                         "4 unwind DW_CFA_nop\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_nop32) {
  cfa_nop_test<uint32_t>(dmem32_.get(), 0xa0000, 0x2000);
}

TEST_F(DwarfCfaTest, cfa_nop64) {
  cfa_nop_test<uint64_t>(dmem64_.get(), 0xa0000, 0x2000);
}

TEST_F(DwarfCfaTest, cfa_offset) {
  memory_.SetData(0x2000, 0x0483);
  DwarfCfa<uint32_t> cfa32(dmem32_.get(), &cie_, &fde_);
  ASSERT_TRUE(cfa32.Eval(0xa0000, 0x2000, 0x2002));

  std::string expected = "4 unwind Raw Data: 0x83 0x04\n"
                         "4 unwind DW_CFA_offset register(3) 4\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());

  ResetLogs();
  memory_.SetData(0x2100, 0x018483);
  DwarfCfa<uint64_t> cfa64(dmem64_.get(), &cie_, &fde_);
  expected = "4 unwind Raw Data: 0x83 0x84 0x01\n"
             "4 unwind DW_CFA_offset register(3) 132\n";
  ASSERT_TRUE(cfa64.Eval(0xa0000, 0x2100, 0x2103));

  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

template <typename AddressType>
void DwarfCfaTest::cfa_restore_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset) {
  memory_.SetData(offset, 0xc2);
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_FALSE(cfa.Eval(pc, offset, offset + 1));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_STATE, cfa.last_error());

  std::string expected = "4 unwind Raw Data: 0xc2\n"
                         "4 unwind DW_CFA_restore register(2)\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ((expected + "4 unwind restore while processing cie.\n").c_str(),
               GetFakeLogPrint().c_str());

  ResetLogs();
  std::unordered_map<uint8_t, DwarfLocation> regs;
  regs[2] = { .type = DWARF_LOCATION_SAME };
  cfa.set_cie_regs(&regs);
  ASSERT_TRUE(cfa.Eval(pc, offset, offset + 1));

  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_restorer32) {
  cfa_restore_test<uint32_t>(dmem32_.get(), 0xa0000, 0x2000);
}

TEST_F(DwarfCfaTest, cfa_restorer64) {
  cfa_restore_test<uint64_t>(dmem64_.get(), 0xa0000, 0x4000);
}

template <typename AddressType>
void DwarfCfaTest::cfa_set_loc_test(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset) {
  uint8_t buffer[1 + sizeof(AddressType)];
  buffer[0] = 0x1;
  AddressType address;
  std::string raw_data("Raw Data: 0x01 ");
  std::string address_str;
  if (sizeof(AddressType) == 4) {
    address = 0x81234578U;
    address_str = "0x81234578";
    raw_data += "0x78 0x45 0x23 0x81";
  } else {
    address = 0x8123456712345678ULL;
    address_str = "0x8123456712345678";
    raw_data += "0x78 0x56 0x34 0x12 0x67 0x45 0x23 0x81";
  }
  memcpy(&buffer[1], &address, sizeof(address));

  memory_.SetMemory(offset, buffer, sizeof(buffer));
  ResetLogs();
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_TRUE(cfa.Eval(pc, offset, offset + 1 + sizeof(AddressType)));
  ASSERT_EQ(address, cfa.cur_pc());

  std::string expected = "4 unwind " + raw_data + "\n";
  expected += "4 unwind DW_CFA_set_loc " + address_str + "\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());

  // Check for a set going back.
  ResetLogs();
  fde_.start_pc = address + 0x10;
  ASSERT_TRUE(cfa.Eval(fde_.start_pc, offset, offset + 1 + sizeof(AddressType)));
  ASSERT_EQ(address, cfa.cur_pc());

  std::string cur_address_str(address_str);
  cur_address_str[cur_address_str.size() - 2]  = '8';
  expected += "4 unwind Warning: PC is moving backwards: old " + cur_address_str;
  expected += " new " + address_str + "\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_set_loc32) {
  cfa_set_loc_test<uint32_t>(dmem32_.get(), 0xa00000, 0x3000);
}

TEST_F(DwarfCfaTest, cfa_set_loc64) {
  cfa_set_loc_test<uint64_t>(dmem64_.get(), 0xa00000, 0x4000);
}

template <typename AddressType>
void DwarfCfaTest::cfa_advance_loc1(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset) {
  memory_.SetData(offset, 0x0402);
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_TRUE(cfa.Eval(pc, offset, offset + 2));
  ASSERT_EQ(pc + 0x10, cfa.cur_pc());

  std::string expected = "4 unwind Raw Data: 0x02 0x04\n"
                         "4 unwind DW_CFA_advance_loc1 4\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_advance_loc1_32) {
  cfa_advance_loc1(dmem32_.get(), 0xa0000, 0x2000);
}

TEST_F(DwarfCfaTest, cfa_advance_loc1_64) {
  cfa_advance_loc1(dmem64_.get(), 0xa0000, 0x2000);
}

template <typename AddressType>
void DwarfCfaTest::cfa_advance_loc2(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset) {
  memory_.SetData(offset, 0x030403);
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_TRUE(cfa.Eval(pc, offset, offset + 2));
  ASSERT_EQ(pc + 0xc10, cfa.cur_pc());

  std::string expected = "4 unwind Raw Data: 0x03 0x04 0x03\n"
                         "4 unwind DW_CFA_advance_loc2 772\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_advance_loc2_32) {
  cfa_advance_loc2(dmem32_.get(), 0xa0000, 0x2000);
}

TEST_F(DwarfCfaTest, cfa_advance_loc2_64) {
  cfa_advance_loc2(dmem64_.get(), 0xa0000, 0x2000);
}

template <typename AddressType>
void DwarfCfaTest::cfa_advance_loc4(DwarfMemory<AddressType>* dmem, uint64_t pc, uint64_t offset) {
  memory_.SetData(offset, 0x02030404);
  memory_.SetData(offset + 4, 0x01);
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  ASSERT_TRUE(cfa.Eval(pc, offset, offset + 2));
  ASSERT_EQ(pc + 0x4080c10, cfa.cur_pc());

  std::string expected = "4 unwind Raw Data: 0x04 0x04 0x03 0x02 0x01\n"
                         "4 unwind DW_CFA_advance_loc4 16909060\n";
  ASSERT_STREQ("", GetFakeLogBuf().c_str());
  ASSERT_STREQ(expected.c_str(), GetFakeLogPrint().c_str());
}

TEST_F(DwarfCfaTest, cfa_advance_loc4_32) {
  cfa_advance_loc4(dmem32_.get(), 0xa0000, 0x2000);
}

TEST_F(DwarfCfaTest, cfa_advance_loc4_64) {
  cfa_advance_loc4(dmem64_.get(), 0xa0000, 0x2000);
}
