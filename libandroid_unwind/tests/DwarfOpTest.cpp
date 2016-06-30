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
#include <vector>

#include <gtest/gtest.h>

#include "Dwarf.h"
#include "DwarfError.h"
#include "DwarfMemory.h"
#include "DwarfOp.h"
#include "Log.h"

#include "LogFake.h"
#include "MemoryFake.h"

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
  void illegal_in_version(uint8_t, std::vector<uint8_t>);

  template <typename AddressType>
  void illegal_in_version3();

  template <typename AddressType>
  void illegal_in_version4();

  template <typename AddressType>
  void not_implemented_opcode();

  template <typename AddressType>
  void op_addr();

  template <typename AddressType>
  void op_deref();

  template <typename AddressType>
  void const_unsigned();

  template <typename AddressType>
  void const_signed();

  template <typename AddressType>
  void const_uleb();

  template <typename AddressType>
  void const_sleb();

  template <typename AddressType>
  void op_dup();

  template <typename AddressType>
  void op_drop();

  template <typename AddressType>
  void op_over();

  template <typename AddressType>
  void op_pick();

  template <typename AddressType>
  void op_swap();

  template <typename AddressType>
  void op_rot();

  template <typename AddressType>
  void op_xderef();

  template <typename AddressType>
  void op_abs();

  template <typename AddressType>
  void op_and();

  template <typename AddressType>
  void op_div();

  template <typename AddressType>
  void op_minus();

  template <typename AddressType>
  void op_mod();

  template <typename AddressType>
  void op_mul();

  template <typename AddressType>
  void op_neg();

  template <typename AddressType>
  void op_not();

  template <typename AddressType>
  void op_or();

  template <typename AddressType>
  void op_plus();

  template <typename AddressType>
  void op_plus_uconst();

  template <typename AddressType>
  void op_shl();

  template <typename AddressType>
  void op_shr();

  template <typename AddressType>
  void op_shra();

  template <typename AddressType>
  void op_xor();

  template <typename AddressType>
  void op_bra();

  template <typename AddressType>
  void op_lit();

  MemoryFake op_memory_;
  MemoryFake regular_memory_;
};

template <typename AddressType>
void DwarfOpTest::illegal_opcode() {
  // Fill the buffer with all of the illegal opcodes.
  std::vector<uint8_t> opcode_buffer = { 0x00, 0x01, 0x02, 0x04, 0x05, 0x07 };
  for (size_t opcode = 0xa0; opcode < 256; opcode++) {
    opcode_buffer.push_back(opcode);
  }
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  for (size_t i = 0; i < opcode_buffer.size(); i++) {
    ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
    ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
    ASSERT_EQ(opcode_buffer[i], dwarf_op.cur_op());
  }
}

TEST_F(DwarfOpTest, dwarf32_illegal_opcode) {
  illegal_opcode<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_opcode) {
  illegal_opcode<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::illegal_in_version(uint8_t version, std::vector<uint8_t>opcode_buffer) {

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  for (size_t i = 0; i < opcode_buffer.size(); i++) {
    ASSERT_FALSE(dwarf_op.Decode(version - 1));
    ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
    ASSERT_EQ(opcode_buffer[i], dwarf_op.cur_op());
  }
}

template <typename AddressType>
void DwarfOpTest::illegal_in_version3() {
  std::vector<uint8_t> opcode_buffer = { 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d };
  op_memory_.SetMemory(0, opcode_buffer);
  illegal_in_version<AddressType>(3, opcode_buffer);
}

TEST_F(DwarfOpTest, dwarf32_illegal_in_version3) {
  illegal_in_version3<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_in_version3) {
  illegal_in_version3<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::illegal_in_version4() {
  std::vector<uint8_t> opcode_buffer = { 0x9e, 0x9f };
  op_memory_.SetMemory(0, opcode_buffer);
  illegal_in_version<AddressType>(4, opcode_buffer);
}

TEST_F(DwarfOpTest, dwarf32_illegal_in_version4) {
  illegal_in_version4<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_illegal_in_version4) {
  illegal_in_version4<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::not_implemented_opcode() {
  std::vector<uint8_t> opcode_buffer = {
    // Push values so that any not implemented ops will return the right error.
    0x08, 0x03,
    0x08, 0x02,
    0x08, 0x01,
    // xderef
    0x18,
    // fbreg
    0x91, 0x01,
    // piece
    0x93, 0x01,
    // xderef_size
    0x95, 0x01,
    // push_object_address
    0x97,
    // call2
    0x98, 0x01, 0x02,
    // call4
    0x99, 0x01, 0x02, 0x03, 0x04,
    // call_ref
    0x9a,
    // form_tls_address
    0x9b,
    // call_frame_cfa
    0x9c,
    // bit_piece
    0x9d, 0x01, 0x01,
    // implicit_value
    0x9e, 0x01,
    // stack_value
    0x9f,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  // Push the stack values.
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));

  while (dwarf_memory.cur_offset() < opcode_buffer.size()) {
    ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
    ASSERT_EQ(DWARF_ERROR_NOT_IMPLEMENTED, dwarf_op.last_error());
  }
}

TEST_F(DwarfOpTest, dwarf32_not_implemented) {
  not_implemented_opcode<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_not_implemented) {
  not_implemented_opcode<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_addr() {
  std::vector<uint8_t> opcode_buffer = { 0x03, 0x12, 0x23, 0x34, 0x45 };
  if (sizeof(AddressType) == 8) {
    opcode_buffer.push_back(0x56);
    opcode_buffer.push_back(0x67);
    opcode_buffer.push_back(0x78);
    opcode_buffer.push_back(0x89);
  }
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x03, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x45342312U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x8978675645342312UL, dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_addr) {
  op_addr<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_addr) {
  op_addr<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_deref() {
  std::vector<uint8_t> opcode_buffer = {
    // Try a dereference with nothing on the stack.
    0x06,
    // Add an address, then dereference.
    0x0a, 0x10, 0x20,
    0x06,
    // Now do another dereference that should fail in memory.
    0x06,
  };
  op_memory_.SetMemory(0, opcode_buffer);
  AddressType value = 0x12345678;
  regular_memory_.SetMemory(0x2010, &value, sizeof(value));

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x06, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(value, dwarf_op.StackAt(0));

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_MEMORY_INVALID, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_deref) {
  op_deref<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_deref) {
  op_deref<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::const_unsigned() {
  std::vector<uint8_t> opcode_buffer = {
    // const1u
    0x08, 0x12,
    0x08, 0xff,
    // const2u
    0x0a, 0x45, 0x12,
    0x0a, 0x00, 0xff,
    // const4u
    0x0c, 0x12, 0x23, 0x34, 0x45,
    0x0c, 0x03, 0x02, 0x01, 0xff,
    // const8u
    0x0e, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    0x0e, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  // const1u
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x08, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x12U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x08, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0xffU, dwarf_op.StackAt(0));

  // const2u
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0a, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x1245U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0a, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  ASSERT_EQ(0xff00U, dwarf_op.StackAt(0));

  // const4u
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0c, dwarf_op.cur_op());
  ASSERT_EQ(5U, dwarf_op.StackSize());
  ASSERT_EQ(0x45342312U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0c, dwarf_op.cur_op());
  ASSERT_EQ(6U, dwarf_op.StackSize());
  ASSERT_EQ(0xff010203U, dwarf_op.StackAt(0));

  // const8u
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0e, dwarf_op.cur_op());
  ASSERT_EQ(7U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x05060708U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x0102030405060708ULL, dwarf_op.StackAt(0));
  }

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0e, dwarf_op.cur_op());
  ASSERT_EQ(8U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0xbaa99887UL, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0xfeeddccbbaa99887ULL, dwarf_op.StackAt(0));
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
  std::vector<uint8_t> opcode_buffer = {
    // const1s
    0x09, 0x12,
    0x09, 0xff,
    // const2s
    0x0b, 0x21, 0x32,
    0x0b, 0x08, 0xff,
    // const4s
    0x0d, 0x45, 0x34, 0x23, 0x12,
    0x0d, 0x01, 0x02, 0x03, 0xff,
    // const8s
    0x0f, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23, 0x12,
    0x0f, 0x04, 0x03, 0x02, 0x01, 0xef, 0xef, 0xef, 0xff,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  // const1s
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x09, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x12U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x09, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-1), dwarf_op.StackAt(0));

  // const2s
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0b, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x3221U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0b, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-248), dwarf_op.StackAt(0));

  // const4s
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0d, dwarf_op.cur_op());
  ASSERT_EQ(5U, dwarf_op.StackSize());
  ASSERT_EQ(0x12233445U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0d, dwarf_op.cur_op());
  ASSERT_EQ(6U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-16580095), dwarf_op.StackAt(0));

  // const8s
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0f, dwarf_op.cur_op());
  ASSERT_EQ(7U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x56677889ULL, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x1223344556677889ULL, dwarf_op.StackAt(0));
  }

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x0f, dwarf_op.cur_op());
  ASSERT_EQ(8U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x01020304U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(static_cast<AddressType>(-4521264810949884LL), dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_const_signed) {
  const_signed<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_const_signed) {
  const_signed<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::const_uleb() {
  std::vector<uint8_t> opcode_buffer = {
    // Single byte ULEB128
    0x10, 0x22,
    0x10, 0x7f,
    // Multi byte ULEB128
    0x10, 0xa2, 0x22,
    0x10, 0xa2, 0x74,
    0x10, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x09,
    0x10, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x79,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  // Single byte ULEB128
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x22U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x7fU, dwarf_op.StackAt(0));

  // Multi byte ULEB128
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x1122U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  ASSERT_EQ(0x3a22U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_EQ(5U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5080c101U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x9101c305080c101ULL, dwarf_op.StackAt(0));
  }

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x10, dwarf_op.cur_op());
  ASSERT_EQ(6U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5080c101U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x79101c305080c101ULL, dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_const_uleb) {
  const_uleb<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_const_uleb) {
  const_uleb<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::const_sleb() {
  std::vector<uint8_t> opcode_buffer = {
    // Single byte SLEB128
    0x11, 0x22,
    0x11, 0x7f,
    // Multi byte SLEB128
    0x11, 0xa2, 0x22,
    0x11, 0xa2, 0x74,
    0x11, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x09,
    0x11,
  };
  if (sizeof(AddressType) == 4) {
    opcode_buffer.push_back(0xb8);
    opcode_buffer.push_back(0xd3);
    opcode_buffer.push_back(0x63);
  } else {
    opcode_buffer.push_back(0x81);
    opcode_buffer.push_back(0x82);
    opcode_buffer.push_back(0x83);
    opcode_buffer.push_back(0x84);
    opcode_buffer.push_back(0x85);
    opcode_buffer.push_back(0x86);
    opcode_buffer.push_back(0x87);
    opcode_buffer.push_back(0x88);
    opcode_buffer.push_back(0x79);
  }
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  // Single byte SLEB128
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x22U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-1), dwarf_op.StackAt(0));

  // Multi byte SLEB128
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x1122U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-1502), dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_EQ(5U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x5080c101U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x9101c305080c101ULL, dwarf_op.StackAt(0));
  }

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x11, dwarf_op.cur_op());
  ASSERT_EQ(6U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(static_cast<AddressType>(-464456), dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(static_cast<AddressType>(-499868564803501823LL), dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_const_sleb) {
  const_sleb<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_const_sleb) {
  const_sleb<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_dup() {
  std::vector<uint8_t> opcode_buffer = {
    // Should fail since nothing is on the stack.
    0x12,
    // Push on a value and dup.
    0x08, 0x15,
    0x12,
    // Do it again.
    0x08, 0x23,
    0x12,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x12, dwarf_op.cur_op());
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x12, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x15U, dwarf_op.StackAt(0));
  ASSERT_EQ(0x15U, dwarf_op.StackAt(1));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x12, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  ASSERT_EQ(0x23U, dwarf_op.StackAt(0));
  ASSERT_EQ(0x23U, dwarf_op.StackAt(1));
  ASSERT_EQ(0x15U, dwarf_op.StackAt(2));
  ASSERT_EQ(0x15U, dwarf_op.StackAt(3));
}

TEST_F(DwarfOpTest, dwarf32_dup) {
  op_dup<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_dup) {
  op_dup<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_drop() {
  std::vector<uint8_t> opcode_buffer = {
    // Push a couple of values.
    0x08, 0x10,
    0x08, 0x20,
    // Drop the values.
    0x13,
    0x13,
    // Attempt to drop empty stack.
    0x13,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x13, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x10U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x13, dwarf_op.cur_op());
  ASSERT_EQ(0U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x13, dwarf_op.cur_op());
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_drop) {
  op_drop<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_drop) {
  op_drop<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_over() {
  std::vector<uint8_t> opcode_buffer = {
    // Push a couple of values.
    0x08, 0x1a,
    0x08, 0xed,
    // Copy a value.
    0x14,
    // Remove all but one element.
    0x13,
    0x13,
    // Provoke a failure with this opcode.
    0x14,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x14, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x1aU, dwarf_op.StackAt(0));
  ASSERT_EQ(0xedU, dwarf_op.StackAt(1));
  ASSERT_EQ(0x1aU, dwarf_op.StackAt(2));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x14, dwarf_op.cur_op());
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_over) {
  op_over<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_over) {
  op_over<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_pick() {
  std::vector<uint8_t> opcode_buffer = {
    // Push a few values.
    0x08, 0x1a,
    0x08, 0xed,
    0x08, 0x34,
    // Copy the value at offset 2.
    0x15, 0x01,
    // Copy the last value in the stack.
    0x15, 0x03,
    // Choose an invalid index.
    0x15, 0x10,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x15, dwarf_op.cur_op());
  ASSERT_EQ(4U, dwarf_op.StackSize());
  ASSERT_EQ(0xedU, dwarf_op.StackAt(0));
  ASSERT_EQ(0x34U, dwarf_op.StackAt(1));
  ASSERT_EQ(0xedU, dwarf_op.StackAt(2));
  ASSERT_EQ(0x1aU, dwarf_op.StackAt(3));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x15, dwarf_op.cur_op());
  ASSERT_EQ(5U, dwarf_op.StackSize());
  ASSERT_EQ(0x1aU, dwarf_op.StackAt(0));
  ASSERT_EQ(0xedU, dwarf_op.StackAt(1));
  ASSERT_EQ(0x34U, dwarf_op.StackAt(2));
  ASSERT_EQ(0xedU, dwarf_op.StackAt(3));
  ASSERT_EQ(0x1aU, dwarf_op.StackAt(4));

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x15, dwarf_op.cur_op());
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_pick) {
  op_pick<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_pick) {
  op_pick<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_swap() {
  std::vector<uint8_t> opcode_buffer = {
    // Push a couple of values.
    0x08, 0x26,
    0x08, 0xab,
    // Swap values.
    0x16,
    // Pop a value to cause a failure.
    0x13,
    0x16,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0xabU, dwarf_op.StackAt(0));
  ASSERT_EQ(0x26U, dwarf_op.StackAt(1));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x16, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x26U, dwarf_op.StackAt(0));
  ASSERT_EQ(0xabU, dwarf_op.StackAt(1));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x16, dwarf_op.cur_op());
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_swap) {
  op_swap<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_swap) {
  op_swap<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_rot() {
  std::vector<uint8_t> opcode_buffer = {
    // Rotate that should cause a failure.
    0x17,
    0x08, 0x10,
    // Only 1 value on stack, should fail.
    0x17,
    0x08, 0x20,
    // Only 2 values on stack, should fail.
    0x17,
    0x08, 0x30,
    // Should rotate properly.
    0x17,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x30U, dwarf_op.StackAt(0));
  ASSERT_EQ(0x20U, dwarf_op.StackAt(1));
  ASSERT_EQ(0x10U, dwarf_op.StackAt(2));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x17, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(0x20U, dwarf_op.StackAt(0));
  ASSERT_EQ(0x10U, dwarf_op.StackAt(1));
  ASSERT_EQ(0x30U, dwarf_op.StackAt(2));
}

TEST_F(DwarfOpTest, dwarf32_rot) {
  op_rot<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_rot) {
  op_rot<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_abs() {
  std::vector<uint8_t> opcode_buffer = {
    // Abs that should fail.
    0x19,
    // A value that is already positive.
    0x08, 0x10,
    0x19,
    // A value that is negative.
    0x11, 0x7f,
    0x19,
    // A value that is large and negative.
    0x11, 0x81, 0x80, 0x80, 0x80,
  };
  if (sizeof(AddressType) == 4) {
    opcode_buffer.push_back(0x08);
  } else {
    opcode_buffer.push_back(0x80);
    opcode_buffer.push_back(0x80);
    opcode_buffer.push_back(0x01);
  }
  opcode_buffer.push_back(0x19);
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x10U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x19, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x10U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x19, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x1U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x19, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(2147483647U, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(4398046511105UL, dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_abs) {
  op_abs<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_abs) {
  op_abs<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_and() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x1b,
    // Push a single value.
    0x08, 0x20,
    // One element stack, and op will fail.
    0x1b,
    // Push another value.
    0x08, 0x02,
    0x1b,
    // Push on two negative values.
    0x11, 0x7c,
    0x11, 0x7f,
    0x1b,
    // Push one negative, one positive.
    0x11, 0x10,
    0x11, 0x7c,
    0x1b,
    // Divide by zero.
    0x11, 0x10,
    0x11, 0x00,
    0x1b,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  // Two positive values.
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1b, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x10U, dwarf_op.StackAt(0));

  // Two negative values.
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1b, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x04U, dwarf_op.StackAt(0));

  // One negative value, one positive value.
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(4U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1b, dwarf_op.cur_op());
  ASSERT_EQ(3U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-4), dwarf_op.StackAt(0));

  // Divide by zero.
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(4U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(5U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_and) {
  op_and<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_and) {
  op_and<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_div() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x1a,
    // Push a single value.
    0x08, 0x48,
    // One element stack, and op will fail.
    0x1a,
    // Push another value.
    0x08, 0xf0,
    0x1a,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1a, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x40U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_div) {
  op_div<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_div) {
  op_div<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_minus() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x1c,
    // Push a single value.
    0x08, 0x48,
    // One element stack, and op will fail.
    0x1c,
    // Push another value.
    0x08, 0x04,
    0x1c,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1c, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x44U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_minus) {
  op_minus<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_minus) {
  op_minus<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_mod() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x1d,
    // Push a single value.
    0x08, 0x47,
    // One element stack, and op will fail.
    0x1d,
    // Push another value.
    0x08, 0x04,
    0x1d,
    // Try a mod of zero.
    0x08, 0x01,
    0x08, 0x00,
    0x1d,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1d, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x03U, dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(3U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_ILLEGAL_VALUE, dwarf_op.last_error());
}

TEST_F(DwarfOpTest, dwarf32_mod) {
  op_mod<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_mod) {
  op_mod<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_mul() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x1e,
    // Push a single value.
    0x08, 0x48,
    // One element stack, and op will fail.
    0x1e,
    // Push another value.
    0x08, 0x04,
    0x1e,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1e, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x120U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_mul) {
  op_mul<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_mul) {
  op_mul<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_neg() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x1f,
    // Push a single value.
    0x08, 0x48,
    0x1f,
    // Push a negative value.
    0x11, 0x7f,
    0x1f,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1f, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-72), dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x1f, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x01U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_neg) {
  op_neg<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_neg) {
  op_neg<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_not() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x20,
    // Push a single value.
    0x08, 0x4,
    0x20,
    // Push a negative value.
    0x11, 0x7c,
    0x20,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x20, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-5), dwarf_op.StackAt(0));

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x20, dwarf_op.cur_op());
  ASSERT_EQ(2U, dwarf_op.StackSize());
  ASSERT_EQ(0x03U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_not) {
  op_not<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_not) {
  op_not<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_or() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x21,
    // Push a single value.
    0x08, 0x48,
    // One element stack, and op will fail.
    0x21,
    // Push another value.
    0x08, 0xf4,
    0x21,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x21, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0xfcU, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_or) {
  op_or<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_or) {
  op_or<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_plus() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x22,
    // Push a single value.
    0x08, 0xff,
    // One element stack, and op will fail.
    0x22,
    // Push another value.
    0x08, 0xf2,
    0x22,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x22, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x1f1U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_plus) {
  op_plus<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_plus) {
  op_plus<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_plus_uconst() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x23,
    // Push a single value.
    0x08, 0x50,
    0x23, 0x80, 0x51,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x23, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x28d0U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_plus_uconst) {
  op_plus_uconst<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_plus_uconst) {
  op_plus_uconst<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_shl() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x24,
    // Push a single value.
    0x08, 0x67,
    // One element stack, and op will fail.
    0x24,
    // Push another value.
    0x08, 0x03,
    0x24,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x24, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x338U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_shl) {
  op_shl<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_shl) {
  op_shl<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_shr() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x25,
    // Push a single value.
    0x11, 0x70,
    // One element stack, and op will fail.
    0x25,
    // Push another value.
    0x08, 0x03,
    0x25,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x25, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  if (sizeof(AddressType) == 4) {
    ASSERT_EQ(0x1ffffffeU, dwarf_op.StackAt(0));
  } else {
    ASSERT_EQ(0x1ffffffffffffffeULL, dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_shr) {
  op_shr<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_shr) {
  op_shr<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_shra() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x26,
    // Push a single value.
    0x11, 0x70,
    // One element stack, and op will fail.
    0x26,
    // Push another value.
    0x08, 0x03,
    0x26,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x26, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(static_cast<AddressType>(-2), dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_shra) {
  op_shra<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_shra) {
  op_shra<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_xor() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x27,
    // Push a single value.
    0x08, 0x11,
    // One element stack, and op will fail.
    0x27,
    // Push another value.
    0x08, 0x41,
    0x27,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(2U, dwarf_op.StackSize());

  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x27, dwarf_op.cur_op());
  ASSERT_EQ(1U, dwarf_op.StackSize());
  ASSERT_EQ(0x50U, dwarf_op.StackAt(0));
}

TEST_F(DwarfOpTest, dwarf32_xor) {
  op_xor<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_xor) {
  op_xor<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_bra() {
  std::vector<uint8_t> opcode_buffer = {
    // No stack, and op will fail.
    0x28,
    // Push on a non-zero value with a positive branch.
    0x08, 0x11,
    0x28, 0x02, 0x01,
    // Push on a zero value with a positive branch.
    0x08, 0x00,
    0x28, 0x05, 0x00,
    // Push on a non-zero value with a negative branch.
    0x08, 0x11,
    0x28, 0xfc, 0xff,
    // Push on a zero value with a negative branch.
    0x08, 0x00,
    0x28, 0xf0, 0xff,
  };
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  ASSERT_FALSE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(DWARF_ERROR_STACK_INDEX_NOT_VALID, dwarf_op.last_error());

  // Push on a non-zero value with a positive branch.
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  uint64_t offset = dwarf_memory.cur_offset() + 3;
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x28, dwarf_op.cur_op());
  ASSERT_EQ(0U, dwarf_op.StackSize());
  ASSERT_EQ(offset + 0x102, dwarf_memory.cur_offset());

  // Push on a zero value with a positive branch.
  dwarf_memory.set_cur_offset(offset);
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  offset = dwarf_memory.cur_offset() + 3;
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x28, dwarf_op.cur_op());
  ASSERT_EQ(0U, dwarf_op.StackSize());
  ASSERT_EQ(offset - 5, dwarf_memory.cur_offset());

  // Push on a non-zero value with a negative branch.
  dwarf_memory.set_cur_offset(offset);
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  offset = dwarf_memory.cur_offset() + 3;
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x28, dwarf_op.cur_op());
  ASSERT_EQ(0U, dwarf_op.StackSize());
  ASSERT_EQ(offset - 4, dwarf_memory.cur_offset());

  // Push on a zero value with a negative branch.
  dwarf_memory.set_cur_offset(offset);
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(1U, dwarf_op.StackSize());

  offset = dwarf_memory.cur_offset() + 3;
  ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX));
  ASSERT_EQ(0x28, dwarf_op.cur_op());
  ASSERT_EQ(0U, dwarf_op.StackSize());
  ASSERT_EQ(offset + 16, dwarf_memory.cur_offset());
}

TEST_F(DwarfOpTest, dwarf32_bra) {
  op_bra<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_bra) {
  op_bra<uint64_t>();
}

template <typename AddressType>
void DwarfOpTest::op_lit() {
  std::vector<uint8_t> opcode_buffer;

  // Verify every lit opcode.
  for (uint8_t op = 0x30; op <= 0x4f; op++) {
    opcode_buffer.push_back(op);
  }
  op_memory_.SetMemory(0, opcode_buffer);

  DwarfMemory<AddressType> dwarf_memory(&op_memory_);
  DwarfOp<AddressType> dwarf_op(&dwarf_memory, &regular_memory_);

  for (uint8_t op = 0x30; op <= 0x4f; op++) {
    ASSERT_TRUE(dwarf_op.Decode(DWARF_VERSION_MAX)) << "Failed op: " << std::hex << op;
    ASSERT_EQ(op, dwarf_op.cur_op());
    ASSERT_EQ(op - 0x30U, dwarf_op.StackAt(0));
  }
}

TEST_F(DwarfOpTest, dwarf32_lit) {
  op_lit<uint32_t>();
}

TEST_F(DwarfOpTest, dwarf64_lit) {
  op_lit<uint64_t>();
}
