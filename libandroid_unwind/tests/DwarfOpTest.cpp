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

#include <ios>

#include <gtest/gtest.h>

#include "Dwarf.h"
#include "DwarfError.h"
#include "DwarfMemory.h"
#include "DwarfOp.h"
#include "Log.h"

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

  template <typename AddressType>
  void illegal_opcode();

  template <typename AddressType>
  void illegal_in_version3();

  template <typename AddressType>
  void illegal_in_version4();

  template <typename AddressType>
  void const_unsigned();

  template <typename AddressType>
  void const_signed();

  template <typename AddressType>
  void constu();

  template <typename AddressType>
  void consts();

  template <typename AddressType>
  void dup();

  template <typename AddressType>
  void drop();

  template <typename AddressType>
  void over();

  template <typename AddressType>
  void pick();

  template <typename AddressType>
  void swap();

  template <typename AddressType>
  void lit();

  MemoryFake op_memory_;
  MemoryFake regular_memory_;
};

template <typename AddressType>
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

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x00, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x01, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x02, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x04, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x05, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x07, dwarf_op.cur_op());

  for (size_t opcode = 0xa0; opcode < 256; opcode++) {
    ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
    ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
    ASSERT_EQ(opcode, dwarf_op.cur_op());
  }
}

TEST_F(DwarfOpTest, dwarf32_illegal_opcode) {
  illegal_opcode<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_opcode) {
  illegal_opcode<uint64_t>();
}

template <typename AddressType>
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

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x97, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x98, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x99, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x9a, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x9b, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x9c, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(2));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x9d, dwarf_op.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_illegal_in_version3) {
  illegal_in_version3<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_in_version3) {
  illegal_in_version3<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::illegal_in_version4() {
  uint8_t opcode_buffer[256];

  opcode_buffer[0] = 0x9e;
  opcode_buffer[1] = 0x9f;
  op_memory_.SetMemory(0, opcode_buffer, 2);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Eval(3));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x9e, dwarf_op.cur_op());

  ASSERT_FALSE(dwarf_op.Eval(3));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
  ASSERT_EQ(0x9f, dwarf_op.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_illegal_in_version4) {
  illegal_in_version4<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_in_version4) {
  illegal_in_version4<uint64_t>();
}

TEST_F(DwarfOpTest, dwarf32_addr) {
  uint8_t opcode_buffer[256];

  opcode_buffer[0] = 0x03;
  opcode_buffer[1] = 0x12;
  opcode_buffer[2] = 0x23;
  opcode_buffer[3] = 0x34;
  opcode_buffer[4] = 0x45;
  op_memory_.SetMemory(0, opcode_buffer, 5);

  DwarfMemory<uint32_t> dwarf_memory(&op_memory_);
  DwarfOp<uint32_t> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x03, dwarf_op.cur_op());
  uint32_t value;
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x45342312U, value);
}

TEST_F(DwarfOpTest, dwarf64_addr) {
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

  DwarfMemory<uint64_t> dwarf_memory(&op_memory_);
  DwarfOp<uint64_t> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x03, dwarf_op.cur_op());
  uint64_t value;
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x8978675645342312UL, value);
}

TEST_F(DwarfOpTest, dwarf32_deref) {
}

TEST_F(DwarfOpTest, dwarf64_deref) {
}

template <typename AddressType>
void DwarfOpTest::const_unsigned() {
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

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  AddressType value;

  // const1u
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x08, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x12U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x08, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0xffU, value);

  // const2u
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0a, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x1245U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0a, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0xff00U, value);

  // const4u
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0c, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x45342312U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0c, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0xff010203U, value);

  // const8u
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0e, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x05060708U, value);
  } else {
    ASSERT_EQ(0x0102030405060708ULL, value);
  }

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0e, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0xbaa99887UL, value);
  } else {
    ASSERT_EQ(0xfeeddccbbaa99887ULL, value);
  }
}

TEST_F(DwarfOpTest, dwarf32_const_unsigned) {
  const_unsigned<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_const_unsigned) {
  const_unsigned<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::const_signed() {
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

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  AddressType value;

  // const1s
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x09, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x12U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x09, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(static_cast<AddressType>(-1), value);

  // const2s
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0b, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x3221U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0b, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(static_cast<AddressType>(-248), value);

  // const4s
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0d, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x12233445U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0d, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(static_cast<AddressType>(-16580095), value);

  // const8s
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0f, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x56677889ULL, value);
  } else {
    ASSERT_EQ(0x1223344556677889ULL, value);
  }

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x0f, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x01020304U, value);
  } else {
    ASSERT_EQ(static_cast<AddressType>(-4521264810949884LL), value);
  }
}

TEST_F(DwarfOpTest, dwarf32_const_signed) {
  const_signed<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_const_signed) {
  const_signed<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::constu() {
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

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  AddressType value;

  // Single byte SLEB128
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x22U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x7fU, value);

  // Multi byte SLEB128
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x1122U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x3a22U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5080c101U, value);
  } else {
    ASSERT_EQ(0x9101c305080c101ULL, value);
  }

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5080c101U, value);
  } else {
    ASSERT_EQ(0x79101c305080c101ULL, value);
  }
}

TEST_F(DwarfOpTest, dwarf32_constu) {
  constu<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_constu) {
  constu<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::consts() {
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
  if (sizeof(AddressType) == 4) {
    opcode_buffer[opcode_offset++] = 0xb8;
    opcode_buffer[opcode_offset++] = 0xd3;
    opcode_buffer[opcode_offset++] = 0x63;
  } else {
    opcode_buffer[opcode_offset++] = 0x81;
    opcode_buffer[opcode_offset++] = 0x82;
    opcode_buffer[opcode_offset++] = 0x83;
    opcode_buffer[opcode_offset++] = 0x84;
    opcode_buffer[opcode_offset++] = 0x85;
    opcode_buffer[opcode_offset++] = 0x86;
    opcode_buffer[opcode_offset++] = 0x87;
    opcode_buffer[opcode_offset++] = 0x88;
    opcode_buffer[opcode_offset++] = 0x79;
  }
  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  AddressType value;

  // Single byte SLEB128
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x22U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(static_cast<AddressType>(-1), value);

  // Multi byte SLEB128
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x1122U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(static_cast<AddressType>(-1502), value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5080c101U, value);
  } else {
    ASSERT_EQ(0x9101c305080c101ULL, value);
  }

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(static_cast<AddressType>(-464456), value);
  } else {
    ASSERT_EQ(static_cast<AddressType>(-499868564803501823LL), value);
  }
}

TEST_F(DwarfOpTest, dwarf32_consts) {
  consts<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_consts) {
  consts<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::dup() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Push on an initial value.
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x15;

  opcode_buffer[opcode_offset++] = 0x12;

  // Push on a new value, and dup again.
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x23;

  opcode_buffer[opcode_offset++] = 0x12;
  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x12, dwarf_op.cur_op());
  AddressType value;
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x15U, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0x15U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x23U, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0x23U, value);
  ASSERT_TRUE(dwarf_op.StackAt(2, &value));
  ASSERT_EQ(0x15U, value);
  ASSERT_TRUE(dwarf_op.StackAt(3, &value));
  ASSERT_EQ(0x15U, value);
}

TEST_F(DwarfOpTest, dwarf32_dup) {
  dup<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_dup) {
  dup<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::drop() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Push a couple of values.
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x1a;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x1a;

  // Drop the values.
  opcode_buffer[opcode_offset++] = 0x13;
  opcode_buffer[opcode_offset++] = 0x13;
  // This should fail.
  opcode_buffer[opcode_offset++] = 0x13;

  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x13, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x13, dwarf_op.cur_op());
  ASSERT_EQ(0U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x13, dwarf_op.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_drop) {
  drop<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_drop) {
  drop<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::over() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Push a couple of values.
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x1a;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0xed;

  // Copy the value.
  opcode_buffer[opcode_offset++] = 0x14;

  // Remove all but one value to provoke failure.
  opcode_buffer[opcode_offset++] = 0x13;
  opcode_buffer[opcode_offset++] = 0x13;
  opcode_buffer[opcode_offset++] = 0x14;

  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x14, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  AddressType value;
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x1aU, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0xedU, value);
  ASSERT_TRUE(dwarf_op.StackAt(2, &value));
  ASSERT_EQ(0x1aU, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x14, dwarf_op.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_over) {
  over<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_over) {
  over<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::pick() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Push a few values.
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x1a;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0xed;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x34;

  // Copy the value at offset 2.
  opcode_buffer[opcode_offset++] = 0x15;
  opcode_buffer[opcode_offset++] = 0x01;

  // Copy the last value in the stack.
  opcode_buffer[opcode_offset++] = 0x15;
  opcode_buffer[opcode_offset++] = 0x03;

  // Choose invalid value.
  opcode_buffer[opcode_offset++] = 0x15;
  opcode_buffer[opcode_offset++] = 0x10;

  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(3U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x15, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  AddressType value;
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0xedU, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0x34U, value);
  ASSERT_TRUE(dwarf_op.StackAt(2, &value));
  ASSERT_EQ(0xedU, value);
  ASSERT_TRUE(dwarf_op.StackAt(3, &value));
  ASSERT_EQ(0x1aU, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x15, dwarf_op.cur_op());
  ASSERT_EQ(5U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x1aU, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0xedU, value);
  ASSERT_TRUE(dwarf_op.StackAt(2, &value));
  ASSERT_EQ(0x34U, value);
  ASSERT_TRUE(dwarf_op.StackAt(3, &value));
  ASSERT_EQ(0xedU, value);
  ASSERT_TRUE(dwarf_op.StackAt(4, &value));
  ASSERT_EQ(0x1aU, value);

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x15, dwarf_op.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_pick) {
  pick<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_pick) {
  pick<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::swap() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Push a couple of values.
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0x26;
  opcode_buffer[opcode_offset++] = 0x08;
  opcode_buffer[opcode_offset++] = 0xab;

  // Swap
  opcode_buffer[opcode_offset++] = 0x16;

  // Pop a value to cause a failure.
  opcode_buffer[opcode_offset++] = 0x13;
  opcode_buffer[opcode_offset++] = 0x16;

  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  AddressType value;
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0xabU, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0x26U, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x16, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.StackAt(0, &value));
  ASSERT_EQ(0x26U, value);
  ASSERT_TRUE(dwarf_op.StackAt(1, &value));
  ASSERT_EQ(0xabU, value);

  ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION));
  ASSERT_EQ(0x16, dwarf_op.cur_op());
}

TEST_F(DwarfOpTest, dwarf32_swap) {
  swap<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_swap) {
  swap<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::lit() {
  uint8_t opcode_buffer[256];
  size_t opcode_offset = 0;

  // Verify every lit opcode.
  for (uint8_t op = 0x30; op <= 0x4f; op++) {
    opcode_buffer[opcode_offset++] = op;
  }
  op_memory_.SetMemory(0, opcode_buffer, opcode_offset);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  AddressType value;
  for (uint8_t op = 0x30; op <= 0x4f; op++) {
    ASSERT_TRUE(dwarf_op.Eval(DWARF_MAX_VALID_VERSION)) << "Failed op " << std::hex << op;
    ASSERT_EQ(op, dwarf_op.cur_op());
    ASSERT_TRUE(dwarf_op.StackAt(0, &value));
    ASSERT_EQ(op - 0x30U, value);
  }
}

TEST_F(DwarfOpTest, dwarf32_lit) {
  lit<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_lit) {
  lit<uint64_t>();
}
