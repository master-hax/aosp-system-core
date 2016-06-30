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

#include <deque>
#include <ios>

#include <gtest/gtest.h>

#include "ArmExidx.h"

#include "log_fake.h"
#include "MemoryFake.h"

class ArmExidxDecodeTest : public ::testing::Test {
 protected:
  void Init(StateArm arm) {
    delete exidx_;
    exidx_ = new ArmExidx(arm, &memory_);
    exidx_->set_debug(true);
  }

  virtual void SetUp() {
    resetLogs();
    Init(StateArm{ .cfa = 0x10000 });

    data_ = exidx_->data();
    data_->clear();
  }

  virtual void TearDown() {
    delete exidx_;
  }

  ArmExidx* exidx_ = nullptr;
  std::deque<uint8_t>* data_;

  MemoryFake memory_;
};

TEST_F(ArmExidxDecodeTest, vsp_incr) {
  // 00xxxxxx: vsp = vsp + (xxxxxx << 2) + 4
  data_->push_back(0x00);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp + 4\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10004U, exidx_->state().cfa);

  resetLogs();
  data_->clear();
  data_->push_back(0x01);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp + 8\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1000cU, exidx_->state().cfa);

  resetLogs();
  data_->clear();
  data_->push_back(0x3f);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp + 256\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1010cU, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, vsp_decr) {
  // 00xxxxxx: vsp = vsp - (xxxxxx << 2) + 4
  data_->push_back(0x40);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp - 4\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0xfffcU, exidx_->state().cfa);

  resetLogs();
  data_->clear();
  data_->push_back(0x41);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp - 8\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0xfff4U, exidx_->state().cfa);

  resetLogs();
  data_->clear();
  data_->push_back(0x7f);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp - 256\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0xfef4U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, refuse_unwind) {
  // 10000000 00000000: Refuse to unwind
  data_->push_back(0x80);
  data_->push_back(0x00);
  ASSERT_FALSE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind Refuse to unwind\n", getFakeLogPrint().c_str());
  ASSERT_EQ(ARM_STATUS_NO_UNWIND, exidx_->status());
}

TEST_F(ArmExidxDecodeTest, pop_up_to_12) {
  // 1000iiii iiiiiiii: Pop up to 12 integer registers
  data_->push_back(0x80);
  data_->push_back(0x01);
  memory_.SetData(0x10000, 0x10);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10004U, exidx_->state().cfa);
  ASSERT_EQ(0x10U, exidx_->state().regs[4]);

  resetLogs();
  data_->push_back(0x8f);
  data_->push_back(0xff);
  for (size_t i = 0; i < 12; i++) {
    memory_.SetData(0x10004 + i * 4, i + 0x20);
  }
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15}\n",
               getFakeLogPrint().c_str());
  ASSERT_EQ(0x10034U, exidx_->state().cfa);
  ASSERT_EQ(0x20U, exidx_->state().regs[4]);
  ASSERT_EQ(0x21U, exidx_->state().regs[5]);
  ASSERT_EQ(0x22U, exidx_->state().regs[6]);
  ASSERT_EQ(0x23U, exidx_->state().regs[7]);
  ASSERT_EQ(0x24U, exidx_->state().regs[8]);
  ASSERT_EQ(0x25U, exidx_->state().regs[9]);
  ASSERT_EQ(0x26U, exidx_->state().regs[10]);
  ASSERT_EQ(0x27U, exidx_->state().regs[11]);
  ASSERT_EQ(0x28U, exidx_->state().regs[12]);
  ASSERT_EQ(0x29U, exidx_->state().regs[13]);
  ASSERT_EQ(0x2aU, exidx_->state().regs[14]);
  ASSERT_EQ(0x2bU, exidx_->state().regs[15]);

  resetLogs();
  data_->push_back(0x81);
  data_->push_back(0x28);
  memory_.SetData(0x10034, 0x11);
  memory_.SetData(0x10038, 0x22);
  memory_.SetData(0x1003c, 0x33);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r7, r9, r12}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10040U, exidx_->state().cfa);
  ASSERT_EQ(0x11U, exidx_->state().regs[7]);
  ASSERT_EQ(0x22U, exidx_->state().regs[9]);
  ASSERT_EQ(0x33U, exidx_->state().regs[12]);
}

TEST_F(ArmExidxDecodeTest, set_vsp_from_register) {
  // 1001nnnn: Set vsp = r[nnnn] (nnnn != 13, 15)
  Init(StateArm{ .cfa = 0x100, .regs = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } });
  data_->push_back(0x90);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = r0\n", getFakeLogPrint().c_str());
  ASSERT_EQ(1U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0x93);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = r3\n", getFakeLogPrint().c_str());
  ASSERT_EQ(4U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0x9e);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = r14\n", getFakeLogPrint().c_str());
  ASSERT_EQ(15U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, reserved_prefix) {
  // 10011101: Reserved as prefix for ARM register to register moves
  data_->push_back(0x9d);
  ASSERT_FALSE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind [Reserved]\n", getFakeLogPrint().c_str());
  ASSERT_EQ(ARM_STATUS_RESERVED, exidx_->status());

  // 10011111: Reserved as prefix for Intel Wireless MMX register to register moves
  resetLogs();
  data_->push_back(0x9f);
  ASSERT_FALSE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind [Reserved]\n", getFakeLogPrint().c_str());
  ASSERT_EQ(ARM_STATUS_RESERVED, exidx_->status());
}

TEST_F(ArmExidxDecodeTest, pop_registers) {
  // 10100nnn: Pop r4-r[4+nnn]
  data_->push_back(0xa0);
  memory_.SetData(0x10000, 0x14);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10004U, exidx_->state().cfa);
  ASSERT_EQ(0x14U, exidx_->state().regs[4]);

  resetLogs();
  data_->push_back(0xa3);
  memory_.SetData(0x10004, 0x20);
  memory_.SetData(0x10008, 0x30);
  memory_.SetData(0x1000c, 0x40);
  memory_.SetData(0x10010, 0x50);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4-r7}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10014U, exidx_->state().cfa);
  ASSERT_EQ(0x20U, exidx_->state().regs[4]);
  ASSERT_EQ(0x30U, exidx_->state().regs[5]);
  ASSERT_EQ(0x40U, exidx_->state().regs[6]);
  ASSERT_EQ(0x50U, exidx_->state().regs[7]);

  resetLogs();
  data_->push_back(0xa7);
  memory_.SetData(0x10014, 0x41);
  memory_.SetData(0x10018, 0x51);
  memory_.SetData(0x1001c, 0x61);
  memory_.SetData(0x10020, 0x71);
  memory_.SetData(0x10024, 0x81);
  memory_.SetData(0x10028, 0x91);
  memory_.SetData(0x1002c, 0xa1);
  memory_.SetData(0x10030, 0xb1);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4-r11}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10034U, exidx_->state().cfa);
  ASSERT_EQ(0x41U, exidx_->state().regs[4]);
  ASSERT_EQ(0x51U, exidx_->state().regs[5]);
  ASSERT_EQ(0x61U, exidx_->state().regs[6]);
  ASSERT_EQ(0x71U, exidx_->state().regs[7]);
  ASSERT_EQ(0x81U, exidx_->state().regs[8]);
  ASSERT_EQ(0x91U, exidx_->state().regs[9]);
  ASSERT_EQ(0xa1U, exidx_->state().regs[10]);
  ASSERT_EQ(0xb1U, exidx_->state().regs[11]);
}

TEST_F(ArmExidxDecodeTest, pop_registers_with_r14) {
  // 10101nnn: Pop r4-r[4+nnn], r14
  data_->push_back(0xa8);
  memory_.SetData(0x10000, 0x12);
  memory_.SetData(0x10004, 0x22);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4, r14}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10008U, exidx_->state().cfa);
  ASSERT_EQ(0x12U, exidx_->state().regs[4]);
  ASSERT_EQ(0x22U, exidx_->state().regs[14]);

  resetLogs();
  data_->push_back(0xab);
  memory_.SetData(0x10008, 0x1);
  memory_.SetData(0x1000c, 0x2);
  memory_.SetData(0x10010, 0x3);
  memory_.SetData(0x10014, 0x4);
  memory_.SetData(0x10018, 0x5);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4-r7, r14}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1001cU, exidx_->state().cfa);
  ASSERT_EQ(0x1U, exidx_->state().regs[4]);
  ASSERT_EQ(0x2U, exidx_->state().regs[5]);
  ASSERT_EQ(0x3U, exidx_->state().regs[6]);
  ASSERT_EQ(0x4U, exidx_->state().regs[7]);
  ASSERT_EQ(0x5U, exidx_->state().regs[14]);

  resetLogs();
  data_->push_back(0xaf);
  memory_.SetData(0x1001c, 0x1a);
  memory_.SetData(0x10020, 0x2a);
  memory_.SetData(0x10024, 0x3a);
  memory_.SetData(0x10028, 0x4a);
  memory_.SetData(0x1002c, 0x5a);
  memory_.SetData(0x10030, 0x6a);
  memory_.SetData(0x10034, 0x7a);
  memory_.SetData(0x10038, 0x8a);
  memory_.SetData(0x1003c, 0x9a);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r4-r11, r14}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10040U, exidx_->state().cfa);
  ASSERT_EQ(0x1aU, exidx_->state().regs[4]);
  ASSERT_EQ(0x2aU, exidx_->state().regs[5]);
  ASSERT_EQ(0x3aU, exidx_->state().regs[6]);
  ASSERT_EQ(0x4aU, exidx_->state().regs[7]);
  ASSERT_EQ(0x5aU, exidx_->state().regs[8]);
  ASSERT_EQ(0x6aU, exidx_->state().regs[9]);
  ASSERT_EQ(0x7aU, exidx_->state().regs[10]);
  ASSERT_EQ(0x8aU, exidx_->state().regs[11]);
  ASSERT_EQ(0x9aU, exidx_->state().regs[14]);
}

TEST_F(ArmExidxDecodeTest, finish) {
  // 10110000: Finish
  data_->push_back(0xb0);
  ASSERT_FALSE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind Finish\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10000U, exidx_->state().cfa);
  ASSERT_EQ(ARM_STATUS_FINISH, exidx_->status());
}

TEST_F(ArmExidxDecodeTest, spare) {
  // 10110001 00000000: Spare
  data_->push_back(0xb1);
  data_->push_back(0x00);
  ASSERT_FALSE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10000U, exidx_->state().cfa);
  ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());

  // 10110001 xxxxyyyy: Spare (xxxx != 0000)
  for (size_t x = 1; x < 16; x++) {
    for (size_t y = 0; y < 16; y++) {
      resetLogs();
      data_->push_back(0xb1);
      data_->push_back((x << 4) | y);
      ASSERT_FALSE(exidx_->Decode()) << "x, y = " << x << ", " << y;
      ASSERT_STREQ("", getFakeLogBuf().c_str()) << "x, y = " << x << ", " << y;
      ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str()) << "x, y = " << x << ", " << y;
      ASSERT_EQ(0x10000U, exidx_->state().cfa) << "x, y = " << x << ", " << y;
      ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());
    }
  }

  // 101101nn: Spare
  for (size_t n = 0; n < 4; n++) {
    resetLogs();
    data_->push_back(0xb4 | n);
    ASSERT_FALSE(exidx_->Decode()) << "n = " << n;
    ASSERT_STREQ("", getFakeLogBuf().c_str()) << "n = " << n;
    ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str()) << "n = " << n;
    ASSERT_EQ(0x10000U, exidx_->state().cfa) << "n = " << n;
    ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());
  }

  // 11000111 00000000: Spare
  resetLogs();
  data_->push_back(0xc7);
  data_->push_back(0x00);
  ASSERT_FALSE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10000U, exidx_->state().cfa);
  ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());

  // 11000111 xxxxyyyy: Spare (xxxx != 0000)
  for (size_t x = 1; x < 16; x++) {
    for (size_t y = 0; y < 16; y++) {
      resetLogs();
      data_->push_back(0xc7);
      data_->push_back(0x10);
      ASSERT_FALSE(exidx_->Decode()) << "x, y = " << x << ", " << y;
      ASSERT_STREQ("", getFakeLogBuf().c_str()) << "x, y = " << x << ", " << y;
      ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str()) << "x, y = " << x << ", " << y;
      ASSERT_EQ(0x10000U, exidx_->state().cfa) << "x, y = " << x << ", " << y;
      ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());
    }
  }

  // 11001yyy: Spare (yyy != 000, 001)
  for (size_t y = 2; y < 8; y++) {
    resetLogs();
    data_->push_back(0xc8 | y);
    ASSERT_FALSE(exidx_->Decode()) << "y = " << y;
    ASSERT_STREQ("", getFakeLogBuf().c_str()) << "y = " << y;
    ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str()) << "y = " << y;
    ASSERT_EQ(0x10000U, exidx_->state().cfa) << "y = " << y;
    ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());
  }

  // 11xxxyyy: Spare (xxx != 000, 001, 010)
  for (size_t x = 3; x < 8; x++) {
    for (size_t y = 0; y < 8; y++) {
      resetLogs();
      data_->push_back(0xc0 | (x << 3) | y);
      ASSERT_FALSE(exidx_->Decode()) << "x, y = " << x << ", " << y;
      ASSERT_STREQ("", getFakeLogBuf().c_str()) << "x, y = " << x << ", " << y;
      ASSERT_STREQ("4 unwind Spare\n", getFakeLogPrint().c_str()) << "x, y = " << x << ", " << y;
      ASSERT_EQ(0x10000U, exidx_->state().cfa) << "x, y = " << x << ", " << y;
      ASSERT_EQ(ARM_STATUS_SPARE, exidx_->status());
    }
  }
}

TEST_F(ArmExidxDecodeTest, pop_registers_under_mask) {
  // 10110001 0000iiii: Pop integer registers {r0, r1, r2, r3}
  data_->push_back(0xb1);
  data_->push_back(0x01);
  memory_.SetData(0x10000, 0x45);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r0}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10004U, exidx_->state().cfa);
  ASSERT_EQ(0x45U, exidx_->state().regs[0]);

  resetLogs();
  data_->push_back(0xb1);
  data_->push_back(0x0a);
  memory_.SetData(0x10004, 0x23);
  memory_.SetData(0x10008, 0x24);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r1, r3}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1000cU, exidx_->state().cfa);
  ASSERT_EQ(0x23U, exidx_->state().regs[1]);
  ASSERT_EQ(0x24U, exidx_->state().regs[3]);

  resetLogs();
  data_->push_back(0xb1);
  data_->push_back(0x0f);
  memory_.SetData(0x1000c, 0x65);
  memory_.SetData(0x10010, 0x54);
  memory_.SetData(0x10014, 0x43);
  memory_.SetData(0x10018, 0x32);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {r0, r1, r2, r3}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1001cU, exidx_->state().cfa);
  ASSERT_EQ(0x65U, exidx_->state().regs[0]);
  ASSERT_EQ(0x54U, exidx_->state().regs[1]);
  ASSERT_EQ(0x43U, exidx_->state().regs[2]);
  ASSERT_EQ(0x32U, exidx_->state().regs[3]);
}

TEST_F(ArmExidxDecodeTest, vsp_large_incr) {
  // 10110010 uleb128: vsp = vsp + 0x204 + (uleb128 << 2)
  data_->push_back(0xb2);
  data_->push_back(0x7f);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp + 1024\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10400U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xb2);
  data_->push_back(0xff);
  data_->push_back(0x02);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp + 2048\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10c00U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xb2);
  data_->push_back(0xff);
  data_->push_back(0x82);
  data_->push_back(0x30);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind vsp = vsp + 3147776\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x311400U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_vfp_fstmfdx) {
  // 10110011 sssscccc: Pop VFP double precision registers D[ssss]-D[ssss+cccc] by FSTMFDX
  data_->push_back(0xb3);
  data_->push_back(0x00);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D0}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1000cU, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xb3);
  data_->push_back(0x48);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D4-D12}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10058U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_vfp8_fstmfdx) {
  // 10111nnn: Pop VFP double precision registers D[8]-D[8+nnn] by FSTMFDX
  data_->push_back(0xb8);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D8}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1000cU, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xbb);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D8-D11}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10030U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xbf);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D8-D15}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10074U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_mmx_wr10) {
  // 11000nnn: Intel Wireless MMX pop wR[10]-wR[10+nnn] (nnn != 6, 7)
  data_->push_back(0xc0);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wR10}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10008U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc2);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wR10-wR12}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10020U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc5);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wR10-wR15}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10050U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_mmx_wr) {
  // 11000110 sssscccc: Intel Wireless MMX pop wR[ssss]-wR[ssss+cccc]
  data_->push_back(0xc6);
  data_->push_back(0x00);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wR0}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10008U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc6);
  data_->push_back(0x25);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wR2-wR7}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10038U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc6);
  data_->push_back(0xff);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wR15-wR30}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x100b8U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_mmx_wcgr) {
  // 11000111 0000iiii: Intel Wireless MMX pop wCGR registes {wCGR0,1,2,3}
  data_->push_back(0xc7);
  data_->push_back(0x01);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wCGR0}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10004U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc7);
  data_->push_back(0x0a);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wCGR1, wCGR3}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1000cU, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc7);
  data_->push_back(0x0f);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {wCGR0, wCGR1, wCGR2, wCGR3}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x1001cU, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_vfp16_vpush) {
  // 11001000 sssscccc: Pop VFP double precision registers d[16+ssss]-D[16+ssss+cccc] by VPUSH
  data_->push_back(0xc8);
  data_->push_back(0x00);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D16}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10008U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc8);
  data_->push_back(0x14);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D17-D21}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10030U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc8);
  data_->push_back(0xff);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D31-D46}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x100b0U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_vfp_vpush) {
  // 11001001 sssscccc: Pop VFP double precision registers d[ssss]-D[ssss+cccc] by VPUSH
  data_->push_back(0xc9);
  data_->push_back(0x00);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D0}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10008U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc9);
  data_->push_back(0x23);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D2-D5}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10028U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xc9);
  data_->push_back(0xff);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D15-D30}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x100a8U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, pop_vfp8_vpush) {
  // 11010nnn: Pop VFP double precision registers D[8]-D[8+nnn] by VPUSH
  data_->push_back(0xd0);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D8}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10008U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xd2);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D8-D10}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10020U, exidx_->state().cfa);

  resetLogs();
  data_->push_back(0xd7);
  ASSERT_TRUE(exidx_->Decode());
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("4 unwind pop {D8-D15}\n", getFakeLogPrint().c_str());
  ASSERT_EQ(0x10060U, exidx_->state().cfa);
}

TEST_F(ArmExidxDecodeTest, verify_no_truncated) {
  // This test verifies that no pattern results in a crash or truncation.
  for (size_t x = 0; x < 256; x++) {
    if (x == 0xb2) {
      // This opcode is followed by an uleb128, so just skip this one.
      continue;
    }
    for (size_t y = 0; y < 256; y++) {
      data_->clear();
      data_->push_back(x);
      data_->push_back(y);
      if (!exidx_->Decode()) {
        ASSERT_NE(ARM_STATUS_TRUNCATED, exidx_->status())
            << "x y = 0x" << std::hex << x << " 0x" << y;
      }
    }
  }
}
