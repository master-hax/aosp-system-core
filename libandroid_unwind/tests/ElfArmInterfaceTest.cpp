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

#include <gtest/gtest.h>

#include <vector>

#include "ElfArmInterface.h"

#include "LogFake.h"
#include "MemoryFake.h"

class ElfArmInterfaceTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
    memory_.Clear();
  }

  MemoryFake memory_;
};

TEST_F(ElfArmInterfaceTest, FindEntry_start_zero) {
  ElfArmInterface interface(&memory_, 0, 80);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfArmInterfaceTest, FindEntry_no_entries) {
  ElfArmInterface interface(&memory_, 0x100, 0);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfArmInterfaceTest, FindEntry_no_valid_memory) {
  ElfArmInterface interface(&memory_, 0x100, 16);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfArmInterfaceTest, FindEntry_ip_before_first) {
  ElfArmInterface interface(&memory_, 0x1000, 8);
  memory_.SetData(0x1000, 0x6000);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfArmInterfaceTest, FindEntry_single_entry_negative_value) {
  ElfArmInterface interface(&memory_, 0x8000, 8);
  memory_.SetData(0x8000, 0x7fffff00);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x7ff0, &entry_offset));
  ASSERT_EQ(0x8000U, entry_offset);
}

TEST_F(ElfArmInterfaceTest, FindEntry_last_check_single_entry) {
  ElfArmInterface interface(&memory_, 0x1000, 8);
  memory_.SetData(0x1000, 0x6000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x7000, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.OverwriteData(0x1000, 0x8000);
  ASSERT_TRUE(interface.FindEntry(0x7004, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);
}

TEST_F(ElfArmInterfaceTest, FindEntry_last_check_multiple_entries) {
  ElfArmInterface interface(&memory_, 0x1000, 16);
  memory_.SetData(0x1000, 0x6000);
  memory_.SetData(0x1008, 0x8000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x9008, &entry_offset));
  ASSERT_EQ(0x1008U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.OverwriteData(0x1000, 0x16000);
  memory_.OverwriteData(0x1008, 0x18000);
  ASSERT_TRUE(interface.FindEntry(0x9100, &entry_offset));
  ASSERT_EQ(0x1008U, entry_offset);
}

TEST_F(ElfArmInterfaceTest, FindEntry_multiple_entries_even) {
  ElfArmInterface interface(&memory_, 0x1000, 32);
  memory_.SetData(0x1000, 0x6000);
  memory_.SetData(0x1008, 0x7000);
  memory_.SetData(0x1010, 0x8000);
  memory_.SetData(0x1018, 0x9000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x9100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.OverwriteData(0x1000, 0x16000);
  memory_.OverwriteData(0x1008, 0x17000);
  memory_.OverwriteData(0x1010, 0x18000);
  memory_.OverwriteData(0x1018, 0x19000);
  ASSERT_TRUE(interface.FindEntry(0x9100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);
}

TEST_F(ElfArmInterfaceTest, FindEntry_multiple_entries_odd) {
  ElfArmInterface interface(&memory_, 0x1000, 40);
  memory_.SetData(0x1000, 0x5000);
  memory_.SetData(0x1008, 0x6000);
  memory_.SetData(0x1010, 0x7000);
  memory_.SetData(0x1018, 0x8000);
  memory_.SetData(0x1020, 0x9000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x8100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.OverwriteData(0x1000, 0x15000);
  memory_.OverwriteData(0x1008, 0x16000);
  memory_.OverwriteData(0x1010, 0x17000);
  memory_.OverwriteData(0x1018, 0x18000);
  memory_.OverwriteData(0x1020, 0x19000);
  ASSERT_TRUE(interface.FindEntry(0x8100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);
}

TEST_F(ElfArmInterfaceTest, iterate) {
  ElfArmInterface interface(&memory_, 0x1000, 40);
  memory_.SetData(0x1000, 0x5000);
  memory_.SetData(0x1008, 0x6000);
  memory_.SetData(0x1010, 0x7000);
  memory_.SetData(0x1018, 0x8000);
  memory_.SetData(0x1020, 0x9000);

  std::vector<arm_ptr_t> entries;
  for (auto addr : interface) {
    entries.push_back(addr);
  }
  ASSERT_EQ(5U, entries.size());
  ASSERT_EQ(0x6000U, entries[0]);
  ASSERT_EQ(0x7008U, entries[1]);
  ASSERT_EQ(0x8010U, entries[2]);
  ASSERT_EQ(0x9018U, entries[3]);
  ASSERT_EQ(0xa020U, entries[4]);

  // Make sure the iterate cached the entries.
  memory_.OverwriteData(0x1000, 0x11000);
  memory_.OverwriteData(0x1008, 0x12000);
  memory_.OverwriteData(0x1010, 0x13000);
  memory_.OverwriteData(0x1018, 0x14000);
  memory_.OverwriteData(0x1020, 0x15000);

  entries.clear();
  for (auto addr : interface) {
    entries.push_back(addr);
  }
  ASSERT_EQ(5U, entries.size());
  ASSERT_EQ(0x6000U, entries[0]);
  ASSERT_EQ(0x7008U, entries[1]);
  ASSERT_EQ(0x8010U, entries[2]);
  ASSERT_EQ(0x9018U, entries[3]);
  ASSERT_EQ(0xa020U, entries[4]);
}
