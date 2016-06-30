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
#include "DwarfStructs.h"
#include "Log.h"

#include "LogFake.h"
#include "MemoryFake.h"

class DwarfCfaTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
    memory_.Clear();

    g_LoggingIndentLevel = 0;

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
    fde_.start_pc = 0x2000;
  }

  template <typename AddressType>
  void cfa_illegal_test(DwarfMemory<AddressType>* dmem, uint64_t offset, size_t index);
  template <typename AddressType>
  void cfa_nop_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_restore_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_restore_extended_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_restore_cfa_offset_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_offset_extended_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_offset_extended_sf_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_set_loc_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_advance_loc1_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_advance_loc2_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_advance_loc4_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_undefined_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_same_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_register_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_state_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_state_cfa_offset_restore_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_def_cfa_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_def_cfa_sf_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_def_cfa_register_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_def_cfa_offset_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_def_cfa_offset_sf_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_def_cfa_expression_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_expression_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_val_offset_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_val_offset_sf_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_val_expression_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_gnu_args_size_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_gnu_negative_offset_extended_test(DwarfMemory<AddressType>* dmem);
  template <typename AddressType>
  void cfa_register_override_test(DwarfMemory<AddressType>* dmem);

  MemoryFake memory_;
  std::unique_ptr<DwarfMemory<uint32_t>> dmem32_;
  std::unique_ptr<DwarfMemory<uint64_t>> dmem64_;
  DwarfCIE cie_;
  DwarfFDE fde_;
};

template <typename AddressType>
void DwarfCfaTest::cfa_illegal_test(DwarfMemory<AddressType>* dmem, uint64_t offset,
                                    size_t index) {
  ResetLogs();
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_FALSE(cfa.GetLocationInfo(fde_.start_pc, offset + index * 4, offset + 1 + index * 4, &loc_regs));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, cfa.last_error());
  ASSERT_EQ(offset + index * 4 + 1, dmem->cur_offset());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = android::base::StringPrintf("4 unwind Raw Data: 0x%02zx\n", index);
    expected += "4 unwind Illegal\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_illegal) {
  for (uint8_t i = 0x17; i < 0x3f; i++) {
    if (i == 0x2e || i == 0x2f) {
      // Skip gnu extension ops.
      continue;
    }
    memory_.SetMemory(0x2000 + i * 4, std::vector<uint8_t>{i});
    cfa_illegal_test<uint32_t>(dmem32_.get(), 0x2000, i);
    cfa_illegal_test<uint64_t>(dmem64_.get(), 0x2000, i);
  }
}

template <typename AddressType>
void DwarfCfaTest::cfa_nop_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x2000, std::vector<uint8_t>{0x00});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x2000, 0x2001, &loc_regs));
  ASSERT_EQ(0x2001U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x00\n"
                           "4 unwind DW_CFA_nop\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_nop_32) {
  cfa_nop_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_nop_64) {
  cfa_nop_test<uint64_t>(dmem64_.get());
}

TEST_F(DwarfCfaTest, cfa_offset) {
  memory_.SetMemory(0x2000, std::vector<uint8_t>{0x83, 0x04});
  DwarfCfa<uint32_t> cfa32(dmem32_.get(), &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa32.GetLocationInfo(fde_.start_pc, 0x2000, 0x2002, &loc_regs));
  ASSERT_EQ(0x2002U, dmem32_->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(3);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(32U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x83 0x04\n"
                           "4 unwind DW_CFA_offset register(3) 4\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  memory_.SetMemory(0x2100, std::vector<uint8_t>{0x83, 0x84, 0x01});
  DwarfCfa<uint64_t> cfa64(dmem64_.get(), &cie_, &fde_);
  loc_regs.clear();

  ASSERT_TRUE(cfa64.GetLocationInfo(fde_.start_pc, 0x2100, 0x2103, &loc_regs));
  ASSERT_EQ(0x2103U, dmem64_->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(3);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(1056U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x83 0x84 0x01\n"
                           "4 unwind DW_CFA_offset register(3) 132\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

template <typename AddressType>
void DwarfCfaTest::cfa_offset_extended_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x500, std::vector<uint8_t>{0x05, 0x03, 0x02});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x500, 0x503, &loc_regs));
  ASSERT_EQ(0x503U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(3);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(2U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x05 0x03 0x02\n"
                           "4 unwind DW_CFA_offset_extended register(3) 2\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x1500, std::vector<uint8_t>{0x05, 0x81, 0x01, 0x82, 0x12});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x1500, 0x1505, &loc_regs));
  ASSERT_EQ(0x1505U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(129);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(2306U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x05 0x81 0x01 0x82 0x12\n"
                           "4 unwind DW_CFA_offset_extended register(129) 2306\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_offset_extended_32) {
  cfa_offset_extended_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_offset_extended_64) {
  cfa_offset_extended_test<uint64_t>(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_offset_extended_sf_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x500, std::vector<uint8_t>{0x11, 0x05, 0x10});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x500, 0x503, &loc_regs));
  ASSERT_EQ(0x503U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(5);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(0x80U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x11 0x05 0x10\n"
                           "4 unwind DW_CFA_offset_extended_sf register(5) 16\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  // Check a negative value for the offset.
  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x1500, std::vector<uint8_t>{0x11, 0x86, 0x01, 0xff, 0x7f});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x1500, 0x1505, &loc_regs));
  ASSERT_EQ(0x1505U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(134);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(static_cast<uint64_t>(-8), location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x11 0x86 0x01 0xff 0x7f\n"
                           "4 unwind DW_CFA_offset_extended_sf register(134) -1\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_offset_extended_sf_32) {
  cfa_offset_extended_sf_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_offset_extended_sf_64) {
  cfa_offset_extended_sf_test<uint64_t>(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_restore_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x2000, std::vector<uint8_t>{0xc2});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_FALSE(cfa.GetLocationInfo(fde_.start_pc, 0x2000, 0x2001, &loc_regs));
  ASSERT_EQ(0U, loc_regs.size());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_STATE, cfa.last_error());
  ASSERT_EQ(0x2001U, dmem->cur_offset());

  std::string expected = "4 unwind restore while processing cie\n";
  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected = "4 unwind Raw Data: 0xc2\n"
               "4 unwind DW_CFA_restore register(2)\n" + expected;
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  dwarf_loc_regs_t cie_loc_regs;
  cie_loc_regs[2] = { .type = DWARF_LOCATION_SAME };
  cfa.set_cie_loc_regs(&cie_loc_regs);
  memory_.SetMemory(0x3000, std::vector<uint8_t>{0x82, 0x04, 0xc2});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x3000, 0x3003, &loc_regs));
  ASSERT_EQ(0x3003U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(2);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_SAME, location->second.type);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x82 0x04\n"
                           "4 unwind DW_CFA_offset register(2) 4\n"
                           "4 unwind Raw Data: 0xc2\n"
                           "4 unwind DW_CFA_restore register(2)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_restore_32) {
  cfa_restore_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_restore_64) {
  cfa_restore_test<uint64_t>(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_restore_extended_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x4000, std::vector<uint8_t>{0x06, 0x08});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_FALSE(cfa.GetLocationInfo(fde_.start_pc, 0x4000, 0x4002, &loc_regs));
  ASSERT_EQ(0U, loc_regs.size());
  ASSERT_EQ(0x4002U, dmem->cur_offset());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_STATE, cfa.last_error());

  std::string expected = "4 unwind restore while processing cie\n";
  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected = "4 unwind Raw Data: 0x06 0x08\n"
               "4 unwind DW_CFA_restore_extended register(8)\n" + expected;
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x5000, std::vector<uint8_t>{0x05, 0x82, 0x02, 0x04, 0x06, 0x82, 0x02});
  dwarf_loc_regs_t cie_loc_regs;
  cie_loc_regs[258] = { .type = DWARF_LOCATION_SAME };
  cfa.set_cie_loc_regs(&cie_loc_regs);

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x5000, 0x5007, &loc_regs));
  ASSERT_EQ(0x5007U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(258);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_SAME, location->second.type);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x05 0x82 0x02 0x04\n"
                           "4 unwind DW_CFA_offset_extended register(258) 4\n"
                           "4 unwind Raw Data: 0x06 0x82 0x02\n"
                           "4 unwind DW_CFA_restore_extended register(258)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_restore_extended_32) {
  cfa_restore_extended_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_restore_extended_64) {
  cfa_restore_extended_test<uint64_t>(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_set_loc_test(DwarfMemory<AddressType>* dmem) {
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

  memory_.SetMemory(0x50, buffer, sizeof(buffer));
  ResetLogs();
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x50, 0x51 + sizeof(AddressType), &loc_regs));
  ASSERT_EQ(0x51 + sizeof(AddressType), dmem->cur_offset());
  ASSERT_EQ(address, cfa.cur_pc());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind " + raw_data + "\n";
    expected += "4 unwind DW_CFA_set_loc " + address_str + "\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  // Check for a set going back.
  ResetLogs();
  loc_regs.clear();
  fde_.start_pc = address + 0x10;
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x50, 0x51 + sizeof(AddressType), &loc_regs));
  ASSERT_EQ(0x51 + sizeof(AddressType), dmem->cur_offset());
  ASSERT_EQ(address, cfa.cur_pc());
  ASSERT_EQ(0U, loc_regs.size());

  std::string cur_address_str(address_str);
  cur_address_str[cur_address_str.size() - 2]  = '8';
  std::string expected = "4 unwind Warning: PC is moving backwards: old " + cur_address_str +
                         " new " + address_str + "\n";
  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected = "4 unwind " + raw_data + "\n" + 
               "4 unwind DW_CFA_set_loc " + address_str + "\n" + expected;
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_set_loc_32) {
  cfa_set_loc_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_set_loc_64) {
  cfa_set_loc_test<uint64_t>(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_advance_loc1_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x200, std::vector<uint8_t>{0x02, 0x04});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x202, &loc_regs));
  ASSERT_EQ(0x202U, dmem->cur_offset());
  ASSERT_EQ(fde_.start_pc + 0x10, cfa.cur_pc());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x02 0x04\n"
                           "4 unwind DW_CFA_advance_loc1 4\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_advance_loc1_32) {
  cfa_advance_loc1_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_advance_loc1_64) {
  cfa_advance_loc1_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_advance_loc2_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x600, std::vector<uint8_t>{0x03, 0x04, 0x03});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x600, 0x603, &loc_regs));
  ASSERT_EQ(0x603U, dmem->cur_offset());
  ASSERT_EQ(fde_.start_pc + 0xc10U, cfa.cur_pc());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x03 0x04 0x03\n"
                           "4 unwind DW_CFA_advance_loc2 772\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_advance_loc2_32) {
  cfa_advance_loc2_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_advance_loc2_64) {
  cfa_advance_loc2_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_advance_loc4_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x500, std::vector<uint8_t>{0x04, 0x04, 0x03, 0x02, 0x01});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x500, 0x505, &loc_regs));
  ASSERT_EQ(0x505U, dmem->cur_offset());
  ASSERT_EQ(fde_.start_pc + 0x4080c10, cfa.cur_pc());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x04 0x04 0x03 0x02 0x01\n"
                           "4 unwind DW_CFA_advance_loc4 16909060\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_advance_loc4_32) {
  cfa_advance_loc4_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_advance_loc4_64) {
  cfa_advance_loc4_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_undefined_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0xa00, std::vector<uint8_t>{0x07, 0x09});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0xa00, 0xa02, &loc_regs));
  ASSERT_EQ(0xa02U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x07 0x09\n"
                           "4 unwind DW_CFA_undefined register(9)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  dwarf_loc_regs_t cie_loc_regs;
  cie_loc_regs[129] = { .type = DWARF_LOCATION_SAME };
  cfa.set_cie_loc_regs(&cie_loc_regs);
  memory_.SetMemory(0x1a00, std::vector<uint8_t>{0x07, 0x81, 0x01});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x1a00, 0x1a03, &loc_regs));
  ASSERT_EQ(0x1a03U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x07 0x81 0x01\n"
                           "4 unwind DW_CFA_undefined register(129)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_undefined_32) {
  cfa_undefined_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_undefined_64) {
  cfa_undefined_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_same_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x08, 0x7f});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x102, &loc_regs));
  ASSERT_EQ(0x102U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(127);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_SAME, location->second.type);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x08 0x7f\n"
                           "4 unwind DW_CFA_same_value register(127)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x2100, std::vector<uint8_t>{0x08, 0xff, 0x01});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x2100, 0x2103, &loc_regs));
  ASSERT_EQ(0x2103U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(255);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_SAME, location->second.type);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x08 0xff 0x01\n"
                           "4 unwind DW_CFA_same_value register(255)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_same_32) {
  cfa_same_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_same_64) {
  cfa_same_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_register_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x300, std::vector<uint8_t>{0x09, 0x02, 0x01});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x300, 0x303, &loc_regs));
  ASSERT_EQ(0x303U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(2);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_REGISTER, location->second.type);
  ASSERT_EQ(1U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x09 0x02 0x01\n"
                           "4 unwind DW_CFA_register register(2) register(1)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x4300, std::vector<uint8_t>{0x09, 0xff, 0x01, 0xff, 0x03});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x4300, 0x4305, &loc_regs));
  ASSERT_EQ(0x4305U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(255);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_REGISTER, location->second.type);
  ASSERT_EQ(511U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x09 0xff 0x01 0xff 0x03\n"
                           "4 unwind DW_CFA_register register(255) register(511)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_register_32) {
  cfa_register_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_register_64) {
  cfa_register_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_state_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x300, std::vector<uint8_t>{0x0a});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x300, 0x301, &loc_regs));
  ASSERT_EQ(0x301U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0a\n"
                           "4 unwind DW_CFA_remember_state\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  memory_.SetMemory(0x4300, std::vector<uint8_t>{0x0b});

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x4300, 0x4301, &loc_regs));
  ASSERT_EQ(0x4301U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0b\n"
                           "4 unwind DW_CFA_restore_state\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  memory_.SetMemory(0x2000, std::vector<uint8_t>{0x85, 0x02, 0x0a, 0x86, 0x04, 0x0b});

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x2000, 0x2005, &loc_regs));
  ASSERT_EQ(0x2005U, dmem->cur_offset());
  ASSERT_EQ(2U, loc_regs.size());
  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
  ASSERT_NE(loc_regs.end(), loc_regs.find(6));

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x2000, 0x2006, &loc_regs));
  ASSERT_EQ(0x2006U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_NE(loc_regs.end(), loc_regs.find(5));

  ResetLogs();
  memory_.SetMemory(0x6000,
                    std::vector<uint8_t>{0x0a, 0x85, 0x02, 0x0a, 0x86, 0x04, 0x0a,
                                         0x87, 0x01, 0x0a, 0x89, 0x05, 0x0b, 0x0b,
                                         0x0b, 0x0b, 0x0b});

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x6000, 0x600c, &loc_regs));
  ASSERT_EQ(0x600cU, dmem->cur_offset());
  ASSERT_EQ(4U, loc_regs.size());
  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
  ASSERT_NE(loc_regs.end(), loc_regs.find(6));
  ASSERT_NE(loc_regs.end(), loc_regs.find(7));
  ASSERT_NE(loc_regs.end(), loc_regs.find(9));

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x6000, 0x600d, &loc_regs));
  ASSERT_EQ(0x600dU, dmem->cur_offset());
  ASSERT_EQ(3U, loc_regs.size());
  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
  ASSERT_NE(loc_regs.end(), loc_regs.find(6));
  ASSERT_NE(loc_regs.end(), loc_regs.find(7));

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x6000, 0x600e, &loc_regs));
  ASSERT_EQ(0x600eU, dmem->cur_offset());
  ASSERT_EQ(2U, loc_regs.size());
  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
  ASSERT_NE(loc_regs.end(), loc_regs.find(6));

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x6000, 0x600f, &loc_regs));
  ASSERT_EQ(0x600fU, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_NE(loc_regs.end(), loc_regs.find(5));

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x6000, 0x6010, &loc_regs));
  ASSERT_EQ(0x6010U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x6000, 0x6011, &loc_regs));
  ASSERT_EQ(0x6011U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());
}

TEST_F(DwarfCfaTest, cfa_state_32) {
  cfa_state_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_state_64) {
  cfa_state_test(dmem64_.get());
}

// This test verifies that the cfa offset is saved and restored properly.
// Even though the spec is not clear about whether the offset is also
// restored, the gcc unwinder does, and libunwind does too.
template <typename AddressType>
void DwarfCfaTest::cfa_state_cfa_offset_restore_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x3000, std::vector<uint8_t>{0x0a, 0x0e, 0x40, 0x0b});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;
  loc_regs[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 5, 100 } };

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x3000, 0x3004, &loc_regs));
  ASSERT_EQ(0x3004U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(5U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(100U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0a\n"
                           "4 unwind DW_CFA_remember_state\n"
                           "4 unwind Raw Data: 0x0e 0x40\n"
                           "4 unwind DW_CFA_def_cfa_offset 64\n"
                           "4 unwind Raw Data: 0x0b\n"
                           "4 unwind DW_CFA_restore_state\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_state_cfa_offset_restore_32) {
  cfa_state_cfa_offset_restore_test<uint32_t>(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_state_cfa_offset_restore_64) {
  cfa_state_cfa_offset_restore_test<uint64_t>(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_def_cfa_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x0c, 0x7f, 0x74});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x103, &loc_regs));
  ASSERT_EQ(0x103U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(0x7fU, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0x74U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0c 0x7f 0x74\n"
                           "4 unwind DW_CFA_def_cfa register(127) 116\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x200, std::vector<uint8_t>{0x0c, 0xff, 0x02, 0xf4, 0x04});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x205, &loc_regs));
  ASSERT_EQ(0x205U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(0x17fU, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0x274U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0c 0xff 0x02 0xf4 0x04\n"
                           "4 unwind DW_CFA_def_cfa register(383) 628\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_32) {
  cfa_def_cfa_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_64) {
  cfa_def_cfa_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_def_cfa_sf_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x12, 0x30, 0x25});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x103, &loc_regs));
  ASSERT_EQ(0x103U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(0x30U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0x128U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x12 0x30 0x25\n"
                           "4 unwind DW_CFA_def_cfa_sf register(48) 37\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  // Test a negative value.
  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x200, std::vector<uint8_t>{0x12, 0xa3, 0x01, 0xfa, 0x7f});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x205, &loc_regs));
  ASSERT_EQ(0x205U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(0xa3U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(static_cast<uint64_t>(-48), loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x12 0xa3 0x01 0xfa 0x7f\n"
                           "4 unwind DW_CFA_def_cfa_sf register(163) -6\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_sf_32) {
  cfa_def_cfa_sf_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_sf_64) {
  cfa_def_cfa_sf_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_def_cfa_register_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x0d, 0x72});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x102, &loc_regs));
  ASSERT_EQ(0x102U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(0x72U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0d 0x72\n"
                           "4 unwind DW_CFA_def_cfa_register register(114)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x200, std::vector<uint8_t>{0x0d, 0xf9, 0x20});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x203, &loc_regs));
  ASSERT_EQ(0x203U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(0x1079U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0d 0xf9 0x20\n"
                           "4 unwind DW_CFA_def_cfa_register register(4217)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_register_32) {
  cfa_def_cfa_register_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_register_64) {
  cfa_def_cfa_register_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_def_cfa_offset_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x0e, 0x59});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  // This fails because the cfa is not defined as a register.
  ASSERT_FALSE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x102, &loc_regs));
  ASSERT_EQ(0U, loc_regs.size());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_STATE, cfa.last_error());

  std::string expected = "4 unwind Attempt to set offset, but cfa is not set to a register.\n";
  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected = "4 unwind Raw Data: 0x0e 0x59\n"
               "4 unwind DW_CFA_def_cfa_offset 89\n" + expected;
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  loc_regs[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 3 } };

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x102, &loc_regs));
  ASSERT_EQ(0x102U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(3U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0x59U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0e 0x59\n"
                           "4 unwind DW_CFA_def_cfa_offset 89\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  memory_.SetMemory(0x200, std::vector<uint8_t>{0x0e, 0xd4, 0x0a});
  loc_regs.clear();
  loc_regs[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 3 } };

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x203, &loc_regs));
  ASSERT_EQ(0x203U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(3U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0x554U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0e 0xd4 0x0a\n"
                           "4 unwind DW_CFA_def_cfa_offset 1364\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_offset_32) {
  cfa_def_cfa_offset_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_offset_64) {
  cfa_def_cfa_offset_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_def_cfa_offset_sf_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x13, 0x23});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  // This fails because the cfa is not defined as a register.
  ASSERT_FALSE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x102, &loc_regs));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_STATE, cfa.last_error());

  std::string expected = "4 unwind Attempt to set offset, but cfa is not set to a register.\n";
  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected = "4 unwind Raw Data: 0x13 0x23\n"
               "4 unwind DW_CFA_def_cfa_offset_sf 35\n" + expected;
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  loc_regs[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 3 } };

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x102, &loc_regs));
  ASSERT_EQ(0x102U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(3U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(0x118U, loc_regs[CFA_REG].values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x13 0x23\n"
                           "4 unwind DW_CFA_def_cfa_offset_sf 35\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  // Negative offset.
  ResetLogs();
  memory_.SetMemory(0x200, std::vector<uint8_t>{0x13, 0xf6, 0x7f});
  loc_regs.clear();
  loc_regs[CFA_REG] = { .type = DWARF_LOCATION_REGISTER, .values = { 3 } };

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x203, &loc_regs));
  ASSERT_EQ(0x203U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  ASSERT_EQ(DWARF_LOCATION_REGISTER, loc_regs[CFA_REG].type);
  ASSERT_EQ(3U, loc_regs[CFA_REG].values[0]);
  ASSERT_EQ(static_cast<AddressType>(-80), static_cast<AddressType>(loc_regs[CFA_REG].values[1]));

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x13 0xf6 0x7f\n"
                           "4 unwind DW_CFA_def_cfa_offset_sf -10\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_offset_sf_32) {
  cfa_def_cfa_offset_sf_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_offset_sf_64) {
  cfa_def_cfa_offset_sf_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_def_cfa_expression_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x0f, 0x04, 0x01, 0x02, 0x03, 0x04});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x106, &loc_regs));
  ASSERT_EQ(0x106U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x0f 0x04 0x01 0x02 0x03 0x04\n"
                           "4 unwind DW_CFA_def_cfa_expression 4\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  std::vector<uint8_t> ops{0x0f, 0x81, 0x01};
  std::string expected = "4 unwind Raw Data: 0x0f 0x81 0x01";
  for (uint8_t i = 3; i < 132; i++) {
    ops.push_back(i - 1);
    expected += android::base::StringPrintf(" 0x%02x", i - 1);
    if (((i + 1) % 10) == 0) {
      expected += "\n4 unwind Raw Data:";
    }
  }
  expected += '\n';
  memory_.SetMemory(0x200, ops);
  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x284, &loc_regs));
  ASSERT_EQ(0x284U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected += "4 unwind DW_CFA_def_cfa_expression 129\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_expression_32) {
  cfa_def_cfa_expression_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_def_cfa_expression_64) {
  cfa_def_cfa_expression_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_expression_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x10, 0x04, 0x02, 0x40, 0x20});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x105, &loc_regs));
  ASSERT_EQ(0x105U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(4);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_EXPRESSION, location->second.type);
  ASSERT_EQ(2U, location->second.values[0]);
  ASSERT_EQ(0x105U, location->second.values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x10 0x04 0x02 0x40 0x20\n"
                           "4 unwind DW_CFA_expression register(4) 2\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  std::vector<uint8_t> ops{0x10, 0xff, 0x01, 0x82, 0x01};
  std::string expected = "4 unwind Raw Data: 0x10 0xff 0x01 0x82 0x01";
  for (uint8_t i = 5; i < 135; i++) {
    ops.push_back(i - 4);
    expected += android::base::StringPrintf(" 0x%02x", i - 4);
    if (((i + 1) % 10) == 0) {
      expected += "\n4 unwind Raw Data:";
    }
  }
  expected += "\n4 unwind DW_CFA_expression register(255) 130\n";

  memory_.SetMemory(0x200, ops);
  loc_regs.clear();
  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x200, 0x287, &loc_regs));
  ASSERT_EQ(0x287U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(255);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_EXPRESSION, location->second.type);
  ASSERT_EQ(130U, location->second.values[0]);
  ASSERT_EQ(0x287U, location->second.values[1]);

  if (!(g_LoggingFlags & LOGGING_FLAG_ENABLE_OP)) {
    expected = "";
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_expression_32) {
  cfa_expression_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_expression_64) {
  cfa_expression_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_val_offset_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x14, 0x45, 0x54});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x103, &loc_regs));
  ASSERT_EQ(0x103U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(69);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_VAL_OFFSET, location->second.type);
  ASSERT_EQ(0x2a0U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x14 0x45 0x54\n"
                           "4 unwind DW_CFA_val_offset register(69) 84\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x400, std::vector<uint8_t>{0x14, 0xa2, 0x02, 0xb4, 0x05});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x400, 0x405, &loc_regs));
  ASSERT_EQ(0x405U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(290);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_VAL_OFFSET, location->second.type);
  ASSERT_EQ(0x15a0U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x14 0xa2 0x02 0xb4 0x05\n"
                           "4 unwind DW_CFA_val_offset register(290) 692\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_val_offset_32) {
  cfa_val_offset_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_val_offset_64) {
  cfa_val_offset_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_val_offset_sf_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x15, 0x56, 0x12});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x103, &loc_regs));
  ASSERT_EQ(0x103U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(86);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_VAL_OFFSET, location->second.type);
  ASSERT_EQ(0x90U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x15 0x56 0x12\n"
                           "4 unwind DW_CFA_val_offset_sf register(86) 18\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  // Negative value.
  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0xa00, std::vector<uint8_t>{0x15, 0xff, 0x01, 0xc0, 0x7f});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0xa00, 0xa05, &loc_regs));
  ASSERT_EQ(0xa05U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(255);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_VAL_OFFSET, location->second.type);
  ASSERT_EQ(static_cast<uint64_t>(-512), location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x15 0xff 0x01 0xc0 0x7f\n"
                           "4 unwind DW_CFA_val_offset_sf register(255) -64\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_val_offset_sf_32) {
  cfa_val_offset_sf_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_val_offset_sf_64) {
  cfa_val_offset_sf_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_val_expression_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x100, std::vector<uint8_t>{0x16, 0x05, 0x02, 0x10, 0x20});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x100, 0x105, &loc_regs));
  ASSERT_EQ(0x105U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(5);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_VAL_EXPRESSION, location->second.type);
  ASSERT_EQ(2U, location->second.values[0]);
  ASSERT_EQ(0x105U, location->second.values[1]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x16 0x05 0x02 0x10 0x20\n"
                           "4 unwind DW_CFA_val_expression register(5) 2\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  std::vector<uint8_t> ops{0x16, 0x83, 0x10, 0xa8, 0x01};
  std::string expected = "4 unwind Raw Data: 0x16 0x83 0x10 0xa8 0x01";
  for (uint8_t i = 0; i < 168; i++) {
    ops.push_back(i);
    expected += android::base::StringPrintf(" 0x%02x", i);
    if (((i + 6) % 10) == 0) {
      expected += "\n4 unwind Raw Data:";
    }
  }
  expected += "\n4 unwind DW_CFA_val_expression register(2051) 168\n";

  memory_.SetMemory(0xa00, ops);
  loc_regs.clear();

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0xa00, 0xaad, &loc_regs));
  ASSERT_EQ(0xaadU, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(2051);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_VAL_EXPRESSION, location->second.type);
  ASSERT_EQ(168U, location->second.values[0]);
  ASSERT_EQ(0xaadU, location->second.values[1]);

  if (!g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    expected = "";
  }
  ASSERT_EQ(expected, GetFakeLogPrint());
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_val_expression_32) {
  cfa_val_expression_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_val_expression_64) {
  cfa_val_expression_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_gnu_args_size_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x2000, std::vector<uint8_t>{0x2e, 0x04});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x2000, 0x2002, &loc_regs));
  ASSERT_EQ(0x2002U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x2e 0x04\n"
                           "4 unwind DW_CFA_GNU_args_size 4\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x5000, std::vector<uint8_t>{0x2e, 0xa4, 0x80, 0x04});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x5000, 0x5004, &loc_regs));
  ASSERT_EQ(0x5004U, dmem->cur_offset());
  ASSERT_EQ(0U, loc_regs.size());

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x2e 0xa4 0x80 0x04\n"
                           "4 unwind DW_CFA_GNU_args_size 65572\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_gnu_args_size_32) {
  cfa_gnu_args_size_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_gnu_args_size_64) {
  cfa_gnu_args_size_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_gnu_negative_offset_extended_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x500, std::vector<uint8_t>{0x2f, 0x08, 0x10});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x500, 0x503, &loc_regs));
  ASSERT_EQ(0x503U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(8);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(static_cast<uint64_t>(-16), location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x2f 0x08 0x10\n"
                           "4 unwind DW_CFA_GNU_negative_offset_extended register(8) 16\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());

  ResetLogs();
  loc_regs.clear();
  memory_.SetMemory(0x1500, std::vector<uint8_t>{0x2f, 0x81, 0x02, 0xff, 0x01});

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x1500, 0x1505, &loc_regs));
  ASSERT_EQ(0x1505U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  location = loc_regs.find(257);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_OFFSET, location->second.type);
  ASSERT_EQ(static_cast<uint64_t>(-255), location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x2f 0x81 0x02 0xff 0x01\n"
                           "4 unwind DW_CFA_GNU_negative_offset_extended register(257) 255\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_gnu_negative_offset_extended_32) {
  cfa_gnu_negative_offset_extended_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_gnu_negative_offset_extended_64) {
  cfa_gnu_negative_offset_extended_test(dmem64_.get());
}

template <typename AddressType>
void DwarfCfaTest::cfa_register_override_test(DwarfMemory<AddressType>* dmem) {
  memory_.SetMemory(0x300, std::vector<uint8_t>{0x09, 0x02, 0x01, 0x09, 0x02, 0x04});
  DwarfCfa<AddressType> cfa(dmem, &cie_, &fde_);
  dwarf_loc_regs_t loc_regs;

  ASSERT_TRUE(cfa.GetLocationInfo(fde_.start_pc, 0x300, 0x306, &loc_regs));
  ASSERT_EQ(0x306U, dmem->cur_offset());
  ASSERT_EQ(1U, loc_regs.size());
  auto location = loc_regs.find(2);
  ASSERT_NE(loc_regs.end(), location);
  ASSERT_EQ(DWARF_LOCATION_REGISTER, location->second.type);
  ASSERT_EQ(4U, location->second.values[0]);

  if (g_LoggingFlags & LOGGING_FLAG_ENABLE_OP) {
    std::string expected = "4 unwind Raw Data: 0x09 0x02 0x01\n"
                           "4 unwind DW_CFA_register register(2) register(1)\n"
                           "4 unwind Raw Data: 0x09 0x02 0x04\n"
                           "4 unwind DW_CFA_register register(2) register(4)\n";
    ASSERT_EQ(expected, GetFakeLogPrint());
  } else {
    ASSERT_EQ("", GetFakeLogPrint());
  }
  ASSERT_EQ("", GetFakeLogBuf());
}

TEST_F(DwarfCfaTest, cfa_register_override_32) {
  cfa_register_override_test(dmem32_.get());
}

TEST_F(DwarfCfaTest, cfa_register_override_64) {
  cfa_register_override_test(dmem64_.get());
}
