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

#include <gtest/gtest.h>

#include "Dwarf.h"

#include "LogFake.h"
#include "MemoryFake.h"

constexpr uint8_t DWARF_MAX_VALID_VERSION = 4;

class DwarfOpTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
    op_memory_.Clear();
    regular_memory_.Clear();
  }

  template <typename Dwarf>
  void illegal_opcode();

  template <typename Dwarf>
  void illegal_in_version3();

  template <typename Dwarf>
  void illegal_in_version4();

  template <typename Dwarf, typename AddressType>
  void op_const_unsigned();

  template <typename Dwarf, typename AddressType>
  void op_const_signed();

  template <typename Dwarf, typename AddressType>
  void op_constu();

  template <typename Dwarf, typename AddressType>
  void op_consts();

  MemoryFake op_memory_;
  MemoryFake regular_memory_;
};

template <typename Dwarf>
void DwarfOpTest::illegal_opcode() {
  uint8_t opcode_buffer[256];
  size_t opcode_index = 0;
  opcode_buffer[opcode_index++] = 0x00;
  opcode_buffer[opcode_index++] = 0x01;
  opcode_buffer[opcode_index++] = 0x02;
  opcode_buffer[opcode_index++] = 0x04;
  opcode_buffer[opcode_index++] = 0x05;
  opcode_buffer[opcode_index++] = 0x07;
  for (size_t opcode = 0xa0; opcode < 256; opcode++) {
    opcode_buffer[opcode_index++] = opcode;
  }

  op_memory_.SetMemory(0, opcode_buffer, opcode_index);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x00, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x01, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x02, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x04, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x05, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x07, dwarf.cur_op());

  for (size_t opcode = 0xa0; opcode < 256; opcode++) {
    ASSERT_FALSE(dwarf.EvalOpcode());
    ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
    ASSERT_EQ(opcode, dwarf.cur_op());
  }
}

TEST_F(DwarfOpTest, dwarf32_illegal_opcode) {
  illegal_opcode<Dwarf32>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_opcode) {
  illegal_opcode<Dwarf64>();
}

template <typename Dwarf>
void DwarfOpTest::illegal_in_version3() {
  uint8_t opcode_buffer[256];

  opcode_buffer[0] = 0x97;
  opcode_buffer[1] = 0x98;
  opcode_buffer[2] = 0x99;
  opcode_buffer[3] = 0x9a;
  opcode_buffer[4] = 0x9b;
  opcode_buffer[5] = 0x9c;
  opcode_buffer[6] = 0x9d;
  op_memory_.SetMemory(0, opcode_buffer, 7);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, 2);

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x97, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x98, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x99, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x9a, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x9b, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x9c, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x9d, dwarf.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_illegal_in_version3) {
  illegal_in_version3<Dwarf32>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_in_version3) {
  illegal_in_version3<Dwarf64>();
}

template <typename Dwarf>
void DwarfOpTest::illegal_in_version4() {
  uint8_t opcode_buffer[256];

  opcode_buffer[0] = 0x9e;
  opcode_buffer[1] = 0x9f;
  op_memory_.SetMemory(0, opcode_buffer, 2);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, 3);

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x9e, dwarf.cur_op());

  ASSERT_FALSE(dwarf.EvalOpcode());
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_OPCODE, dwarf.last_error());
  ASSERT_EQ(0x9f, dwarf.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_illegal_in_version4) {
  illegal_in_version4<Dwarf32>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_in_version4) {
  illegal_in_version4<Dwarf64>();
}

TEST_F(DwarfOpTest, dwarf32_op_addr) {
  uint8_t opcode_buffer[256];

  opcode_buffer[0] = 0x03;
  opcode_buffer[1] = 0x12;
  opcode_buffer[2] = 0x23;
  opcode_buffer[3] = 0x34;
  opcode_buffer[4] = 0x45;
  op_memory_.SetMemory(0, opcode_buffer, 5);

  Dwarf32 dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x03, dwarf.cur_op());
  ASSERT_EQ(0x45342312U, dwarf.StackTop());
}

TEST_F(DwarfOpTest, dwarf64_op_addr) {
  uint8_t opcode_buffer[256];

  opcode_buffer[0] = 0x03;
  opcode_buffer[1] = 0x12;
  opcode_buffer[2] = 0x23;
  opcode_buffer[3] = 0x34;
  opcode_buffer[4] = 0x45;
  opcode_buffer[5] = 0x56;
  opcode_buffer[6] = 0x67;
  opcode_buffer[7] = 0x78;
  opcode_buffer[8] = 0x89;
  op_memory_.SetMemory(0, opcode_buffer, 9);

  Dwarf64 dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x03, dwarf.cur_op());
  ASSERT_EQ(0x8978675645342312UL, dwarf.StackTop());
}

template <typename Dwarf, typename AddressType>
void DwarfOpTest::op_const_unsigned() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // const1u
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x12;

  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0xff;

  // const2u
  opcode_buffer[opcode_offset++] = 0x0a;
  opcode_buffer[opcode_offset++] = 0x45;
  opcode_buffer[opcode_offset++] = 0x12;

  opcode_buffer[opcode_offset++] = 0x0a;
  opcode_buffer[opcode_offset++] = 0x00;
  opcode_buffer[opcode_offset++] = 0xff;

  // const4u
  opcode_buffer[opcode_offset++] = 0x0c;
  opcode_buffer[opcode_offset++] = 0x12;
  opcode_buffer[opcode_offset++] = 0x23;
  opcode_buffer[opcode_offset++] = 0x34;
  opcode_buffer[opcode_offset++] = 0x45;

  opcode_buffer[opcode_offset++] = 0x0c;
  opcode_buffer[opcode_offset++] = 0x03;
  opcode_buffer[opcode_offset++] = 0x02;
  opcode_buffer[opcode_offset++] = 0x01;
  opcode_buffer[opcode_offset++] = 0xff;

  // const8u
  opcode_buffer[opcode_offset++] = 0x0e;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x07;
  opcode_buffer[opcode_offset++] = 0x06;
  opcode_buffer[opcode_offset++] = 0x05;
  opcode_buffer[opcode_offset++] = 0x04;
  opcode_buffer[opcode_offset++] = 0x03;
  opcode_buffer[opcode_offset++] = 0x02;
  opcode_buffer[opcode_offset++] = 0x01;

  opcode_buffer[opcode_offset++] = 0x0e;
  opcode_buffer[opcode_offset++] = 0x87;
  opcode_buffer[opcode_offset++] = 0x98;
  opcode_buffer[opcode_offset++] = 0xa9;
  opcode_buffer[opcode_offset++] = 0xba;
  opcode_buffer[opcode_offset++] = 0xcb;
  opcode_buffer[opcode_offset++] = 0xdc;
  opcode_buffer[opcode_offset++] = 0xed;
  opcode_buffer[opcode_offset++] = 0xfe;
  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  // const1u
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x08, dwarf.cur_op());
  ASSERT_EQ(0x12U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x08, dwarf.cur_op());
  ASSERT_EQ(0xffU, dwarf.StackTop());

  // const2u
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0a, dwarf.cur_op());
  ASSERT_EQ(0x1245U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0a, dwarf.cur_op());
  ASSERT_EQ(0xff00U, dwarf.StackTop());

  // const4u
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0c, dwarf.cur_op());
  ASSERT_EQ(0x45342312U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0c, dwarf.cur_op());
  ASSERT_EQ(0xff010203U, dwarf.StackTop());

  // const8u
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0e, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x05060708U, dwarf.StackTop());
  } else {
    ASSERT_EQ(0x0102030405060708ULL, dwarf.StackTop());
  }

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0e, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
  opcode_buffer[opcode_offset++] = 0xfe;
    ASSERT_EQ(0xbaa99887UL, dwarf.StackTop());
  } else {
    ASSERT_EQ(0xfeeddccbbaa99887ULL, dwarf.StackTop());
  }
}

TEST_F(DwarfOpTest, dwarf32_op_const_unsigned) {
  op_const_unsigned<Dwarf32, uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_op_const_unsigned) {
  op_const_unsigned<Dwarf64, uint64_t>();
}

template <typename Dwarf, typename AddressType>
void DwarfOpTest::op_const_signed() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // const1s
  opcode_buffer[opcode_offset++] = 0x09;
  opcode_buffer[opcode_offset++] = 0x12;

  opcode_buffer[opcode_offset++] = 0x09;
  opcode_buffer[opcode_offset++] = 0xff;

  // const2s
  opcode_buffer[opcode_offset++] = 0x0b;
  opcode_buffer[opcode_offset++] = 0x21;
  opcode_buffer[opcode_offset++] = 0x32;

  opcode_buffer[opcode_offset++] = 0x0b;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0xff;

  // const4s
  opcode_buffer[opcode_offset++] = 0x0d;
  opcode_buffer[opcode_offset++] = 0x45;
  opcode_buffer[opcode_offset++] = 0x34;
  opcode_buffer[opcode_offset++] = 0x23;
  opcode_buffer[opcode_offset++] = 0x12;

  opcode_buffer[opcode_offset++] = 0x0d;
  opcode_buffer[opcode_offset++] = 0x01;
  opcode_buffer[opcode_offset++] = 0x02;
  opcode_buffer[opcode_offset++] = 0x03;
  opcode_buffer[opcode_offset++] = 0xff;

  // const8s
  opcode_buffer[opcode_offset++] = 0x0f;
  opcode_buffer[opcode_offset++] = 0x89;
  opcode_buffer[opcode_offset++] = 0x78;
  opcode_buffer[opcode_offset++] = 0x67;
  opcode_buffer[opcode_offset++] = 0x56;
  opcode_buffer[opcode_offset++] = 0x45;
  opcode_buffer[opcode_offset++] = 0x34;
  opcode_buffer[opcode_offset++] = 0x23;
  opcode_buffer[opcode_offset++] = 0x12;

  opcode_buffer[opcode_offset++] = 0x0f;
  opcode_buffer[opcode_offset++] = 0x04;
  opcode_buffer[opcode_offset++] = 0x03;
  opcode_buffer[opcode_offset++] = 0x02;
  opcode_buffer[opcode_offset++] = 0x01;
  opcode_buffer[opcode_offset++] = 0xef;
  opcode_buffer[opcode_offset++] = 0xef;
  opcode_buffer[opcode_offset++] = 0xef;
  opcode_buffer[opcode_offset++] = 0xff;
  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  // const1s
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x09, dwarf.cur_op());
  ASSERT_EQ(0x12U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x09, dwarf.cur_op());
  ASSERT_EQ(static_cast<AddressType>(-1), dwarf.StackTop());

  // const2s
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0b, dwarf.cur_op());
  ASSERT_EQ(0x3221U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0b, dwarf.cur_op());
  ASSERT_EQ(static_cast<AddressType>(-248), dwarf.StackTop());

  // const4s
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0d, dwarf.cur_op());
  ASSERT_EQ(0x12233445U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0d, dwarf.cur_op());
  ASSERT_EQ(static_cast<AddressType>(-16580095), dwarf.StackTop());

  // const8s
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0f, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x56677889ULL, dwarf.StackTop());
  } else {
    ASSERT_EQ(0x1223344556677889ULL, dwarf.StackTop());
  }

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x0f, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x01020304U, dwarf.StackTop());
  } else {
    ASSERT_EQ(static_cast<AddressType>(-4521264810949884LL), dwarf.StackTop());
  }
}

TEST_F(DwarfOpTest, dwarf32_op_const_signed) {
  op_const_signed<Dwarf32, uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_op_const_signed) {
  op_const_signed<Dwarf64, uint64_t>();
}

template <typename Dwarf, typename AddressType>
void DwarfOpTest::op_constu() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Single byte SLEB128
  opcode_buffer[opcode_offset++] = 0x10;
  opcode_buffer[opcode_offset++] = 0x22;

  opcode_buffer[opcode_offset++] = 0x10;
  opcode_buffer[opcode_offset++] = 0x7f;

  // Multi byte SLEB128
  opcode_buffer[opcode_offset++] = 0x10;
  opcode_buffer[opcode_offset++] = 0xa2;
  opcode_buffer[opcode_offset++] = 0x22;

  opcode_buffer[opcode_offset++] = 0x10;
  opcode_buffer[opcode_offset++] = 0xa2;
  opcode_buffer[opcode_offset++] = 0x74;

  opcode_buffer[opcode_offset++] = 0x10;
  opcode_buffer[opcode_offset++] = 0x81;
  opcode_buffer[opcode_offset++] = 0x82;
  opcode_buffer[opcode_offset++] = 0x83;
  opcode_buffer[opcode_offset++] = 0x84;
  opcode_buffer[opcode_offset++] = 0x85;
  opcode_buffer[opcode_offset++] = 0x86;
  opcode_buffer[opcode_offset++] = 0x87;
  opcode_buffer[opcode_offset++] = 0x88;
  opcode_buffer[opcode_offset++] = 0x09;

  opcode_buffer[opcode_offset++] = 0x10;
  opcode_buffer[opcode_offset++] = 0x81;
  opcode_buffer[opcode_offset++] = 0x82;
  opcode_buffer[opcode_offset++] = 0x83;
  opcode_buffer[opcode_offset++] = 0x84;
  opcode_buffer[opcode_offset++] = 0x85;
  opcode_buffer[opcode_offset++] = 0x86;
  opcode_buffer[opcode_offset++] = 0x87;
  opcode_buffer[opcode_offset++] = 0x88;
  opcode_buffer[opcode_offset++] = 0x79;

  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  // Single byte SLEB128
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x10, dwarf.cur_op());
  ASSERT_EQ(0x22U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x10, dwarf.cur_op());
  ASSERT_EQ(0x7fU, dwarf.StackTop());

  // Multi byte SLEB128
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x10, dwarf.cur_op());
  ASSERT_EQ(0x1122U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x10, dwarf.cur_op());
  ASSERT_EQ(0x3a22U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x10, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5990dd31U, dwarf.StackTop());
  } else {
    ASSERT_EQ(0x9101c305080c101ULL, dwarf.StackTop());
  }

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x10, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x7990dd31U, dwarf.StackTop());
  } else {
    ASSERT_EQ(0x79101c305080c101ULL, dwarf.StackTop());
  }
}

TEST_F(DwarfOpTest, dwarf32_op_constu) {
  op_constu<Dwarf32, uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_op_constu) {
  op_constu<Dwarf64, uint64_t>();
}

template <typename Dwarf, typename AddressType>
void DwarfOpTest::op_consts() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Single byte SLEB128
  opcode_buffer[opcode_offset++] = 0x11;
  opcode_buffer[opcode_offset++] = 0x22;

  opcode_buffer[opcode_offset++] = 0x11;
  opcode_buffer[opcode_offset++] = 0x7f;

  // Multi byte SLEB128
  opcode_buffer[opcode_offset++] = 0x11;
  opcode_buffer[opcode_offset++] = 0xa2;
  opcode_buffer[opcode_offset++] = 0x22;

  opcode_buffer[opcode_offset++] = 0x11;
  opcode_buffer[opcode_offset++] = 0xa2;
  opcode_buffer[opcode_offset++] = 0x74;

  opcode_buffer[opcode_offset++] = 0x11;
  opcode_buffer[opcode_offset++] = 0x81;
  opcode_buffer[opcode_offset++] = 0x82;
  opcode_buffer[opcode_offset++] = 0x83;
  opcode_buffer[opcode_offset++] = 0x84;
  opcode_buffer[opcode_offset++] = 0x85;
  opcode_buffer[opcode_offset++] = 0x86;
  opcode_buffer[opcode_offset++] = 0x87;
  opcode_buffer[opcode_offset++] = 0x88;
  opcode_buffer[opcode_offset++] = 0x09;

  opcode_buffer[opcode_offset++] = 0x11;
  opcode_buffer[opcode_offset++] = 0x81;
  opcode_buffer[opcode_offset++] = 0x82;
  opcode_buffer[opcode_offset++] = 0x83;
  opcode_buffer[opcode_offset++] = 0x84;
  opcode_buffer[opcode_offset++] = 0x85;
  opcode_buffer[opcode_offset++] = 0x86;
  opcode_buffer[opcode_offset++] = 0x87;
  opcode_buffer[opcode_offset++] = 0x88;
  opcode_buffer[opcode_offset++] = 0x79;

  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  Dwarf dwarf(&op_memory_, &regular_memory_, 0, DWARF_MAX_VALID_VERSION);

  // Single byte SLEB128
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x11, dwarf.cur_op());
  ASSERT_EQ(0x22U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x11, dwarf.cur_op());
  ASSERT_EQ(static_cast<AddressType>(-1), dwarf.StackTop());

  // Multi byte SLEB128
  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x11, dwarf.cur_op());
  ASSERT_EQ(0x1122U, dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x11, dwarf.cur_op());
  ASSERT_EQ(static_cast<AddressType>(-1502), dwarf.StackTop());

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x11, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5990dd31U, dwarf.StackTop());
  } else {
    ASSERT_EQ(0x9101c305080c101ULL, dwarf.StackTop());
  }

  ASSERT_TRUE(dwarf.EvalOpcode());
  ASSERT_EQ(0x11, dwarf.cur_op());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(static_cast<AddressType>(-107946703), dwarf.StackTop());
  } else {
    ASSERT_EQ(static_cast<AddressType>(-499868564803501823LL), dwarf.StackTop());
  }
}

TEST_F(DwarfOpTest, dwarf32_op_consts) {
  op_consts<Dwarf32, uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_op_consts) {
  op_consts<Dwarf64, uint64_t>();
}
