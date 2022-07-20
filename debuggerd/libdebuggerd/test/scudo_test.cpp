/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <stdlib.h>
#include <unistd.h>

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libdebuggerd/scudo.h"
#include "libdebuggerd/types.h"
#include "unwindstack/AndroidUnwinder.h"
#include "unwindstack/Memory.h"

#include "tombstone.pb.h"

#include "log_fake.h"

// Must match the number of extra pages read in ScudoCrashData::SetErrorInfo.
constexpr uint64_t kMaxPages = 16;

class MemoryAlwaysZero : public unwindstack::Memory {
 public:
  MemoryAlwaysZero() = default;
  virtual ~MemoryAlwaysZero() = default;

  size_t Read(uint64_t addr, void* buffer, size_t size) override {
    char* char_buf = reinterpret_cast<char*>(buffer);
    uint64_t page_size = getpagesize();
    size_t total_read = 0;
    uint64_t addr_page = addr & ~(page_size - 1);
    if (addr_page != addr) {
      if (test_unreadable_addrs_.count(addr_page)) {
        return 0;
      }
      size_t read_size = page_size - (addr - addr_page);
      read_size = read_size > size ? size : read_size;
      memset(char_buf, 0, read_size);
      total_read += read_size;
      size -= read_size;
      addr_page += page_size;
    }
    for (uint64_t read_addr = addr_page; size > 0; read_addr += page_size) {
      if (test_unreadable_addrs_.count(read_addr) != 0) {
        break;
      }
      size_t read_size = size > page_size ? page_size : size;
      memset(&char_buf[read_addr - addr], 0, read_size);
      total_read += read_size;
      size -= read_size;
    }
    if (total_read != 0) {
      test_read_addrs_.insert(addr);
    }
    return total_read;
  }

  void TestAddUnreadableAddress(uint64_t addr) { test_unreadable_addrs_.insert(addr); }

  void TestClearAddresses() {
    test_read_addrs_.clear();
    test_unreadable_addrs_.clear();
  }

  std::set<uint64_t>& test_read_addrs() { return test_read_addrs_; }

 private:
  std::set<uint64_t> test_unreadable_addrs_;

  std::set<uint64_t> test_read_addrs_;
};

// Use hard-coded values for reading scudo data structures since the
// region info does not exist in 32 bit.
#if defined(__LP64__)
std::vector<uint64_t> g_scudo_data_reads = {0x100000, 0x200000, 0x300000};
#else
std::vector<uint64_t> g_scudo_data_reads = {0x100000, 0x300000};
#endif

TEST(ScudoTest, fault_address_invalid) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = false;
  info.untagged_fault_address = 0x5000000;
  info.scudo_stack_depot = 0x1000000;
  info.scudo_region_info = 0x2000000;
  info.scudo_ring_buffer = 0x3000000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));

  // No reads attempted.
  ASSERT_TRUE(memory->test_read_addrs().empty());
}

TEST(ScudoTest, fault_address_unreadable) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x5000000;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  // Mark everything before and after the fault address as unreadable.
  uint64_t unreadable_addr = info.untagged_fault_address - kMaxPages * getpagesize();
  for (size_t i = 0; i < 2 * kMaxPages; i++, unreadable_addr += getpagesize()) {
    memory->TestAddUnreadableAddress(unreadable_addr);
  }

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));

  ASSERT_THAT(memory->test_read_addrs(), testing::UnorderedElementsAreArray(g_scudo_data_reads));
}

TEST(ScudoTest, fault_address_too_small) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
  ASSERT_TRUE(memory->test_read_addrs().empty());

  info.untagged_fault_address = getpagesize() * 15;
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
  ASSERT_TRUE(memory->test_read_addrs().empty());
}

TEST(ScudoTest, fault_address_too_large) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = UINTPTR_MAX;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
  ASSERT_TRUE(memory->test_read_addrs().empty());

  info.untagged_fault_address -= getpagesize() * 15;
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
  ASSERT_TRUE(memory->test_read_addrs().empty());
}

TEST(ScudoTest, scudo_data_read_check) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x500000;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);

  // Mark the stack depot unreadable
  memory->TestAddUnreadableAddress(0x100000);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
#if defined(__LP64__)
  ASSERT_THAT(memory->test_read_addrs(),
              testing::UnorderedElementsAreArray(std::vector<uint64_t>{0x200000, 0x300000}));
#else
  ASSERT_THAT(memory->test_read_addrs(),
              testing::UnorderedElementsAreArray(std::vector<uint64_t>{0x300000}));
#endif

  // The region info does not exist for 32 bit.
#if defined(__LP64__)
  memory->TestClearAddresses();
  // Mark the region info unreadable
  memory->TestAddUnreadableAddress(0x200000);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
  ASSERT_THAT(memory->test_read_addrs(),
              testing::UnorderedElementsAreArray(std::vector<uint64_t>{0x100000, 0x300000}));
#endif

  memory->TestClearAddresses();
  // Mark the ring buffer unreadable
  memory->TestAddUnreadableAddress(0x300000);
  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
#if defined(__LP64__)
  ASSERT_THAT(memory->test_read_addrs(),
              testing::UnorderedElementsAreArray(std::vector<uint64_t>{0x100000, 0x200000}));
#else
  ASSERT_THAT(memory->test_read_addrs(),
              testing::UnorderedElementsAreArray(std::vector<uint64_t>{0x100000}));
#endif
}

TEST(ScudoTest, pages_before_fault_address_unreadable) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x15000124;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);

  uint64_t page_size = getpagesize();
  uint64_t fault_page = info.untagged_fault_address & ~(page_size - 1);
  uint64_t first_read_addr = fault_page - page_size * kMaxPages;

  // Loop through and make a single page before the fault page unreadable.
  for (size_t i = 1; i <= kMaxPages; i++) {
    memory->TestClearAddresses();
    uint64_t unreadable_addr = fault_page - i * page_size;
    SCOPED_TRACE(testing::Message()
                 << "Failed at unreadable address 0x" << std::hex << unreadable_addr);
    std::vector<uint64_t> expected_reads(g_scudo_data_reads);
    if (unreadable_addr != first_read_addr) {
      expected_reads.push_back(first_read_addr);
    }
    expected_reads.push_back(unreadable_addr + page_size);

    memory->TestAddUnreadableAddress(unreadable_addr);
    ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
    ASSERT_THAT(memory->test_read_addrs(), testing::UnorderedElementsAreArray(expected_reads));
  }
}

TEST(ScudoTest, pages_after_fault_address_unreadable) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x15000124;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);

  uint64_t page_size = getpagesize();
  uint64_t fault_page = info.untagged_fault_address & ~(page_size - 1);
  std::vector<uint64_t> reads(g_scudo_data_reads);
  reads.push_back(fault_page - kMaxPages * page_size);
  uint64_t last_read_addr = fault_page + page_size * (kMaxPages - 1);

  // Loop through and make pages after the fault page unreadable.
  for (size_t i = 1; i < kMaxPages; i++) {
    memory->TestClearAddresses();
    uint64_t unreadable_addr = fault_page + i * page_size;
    SCOPED_TRACE(testing::Message()
                 << "Failed at unreadable address 0x" << std::hex << unreadable_addr);

    std::vector<uint64_t> expected_reads(reads);
    if (unreadable_addr != last_read_addr) {
      expected_reads.push_back(unreadable_addr + page_size);
    }

    memory->TestAddUnreadableAddress(unreadable_addr);
    ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
    ASSERT_THAT(memory->test_read_addrs(), testing::UnorderedElementsAreArray(expected_reads));
  }
}

TEST(ScudoTest, holes_in_fault_address_reads) {
  MemoryAlwaysZero* memory = new MemoryAlwaysZero;
  std::shared_ptr<unwindstack::Memory> process_memory(memory);
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x15000124;
  info.scudo_stack_depot = 0x100000;
  info.scudo_region_info = 0x200000;
  info.scudo_ring_buffer = 0x300000;

  Tombstone tombstone;
  unwindstack::AndroidLocalUnwinder unwinder(process_memory);

  std::vector<uint64_t> expected_reads(g_scudo_data_reads);
  uint64_t page_size = getpagesize();
  uint64_t first_read_addr =
      (info.untagged_fault_address & ~(page_size - 1)) - kMaxPages * page_size;
  expected_reads.push_back(first_read_addr);
  // Create a multi-page hole in the read section.
  memory->TestAddUnreadableAddress(first_read_addr + page_size);
  memory->TestAddUnreadableAddress(first_read_addr + 2 * page_size);
  memory->TestAddUnreadableAddress(first_read_addr + 3 * page_size);
  expected_reads.push_back(first_read_addr + 4 * page_size);

  // Create a single page hole in the read section
  memory->TestAddUnreadableAddress(first_read_addr + 6 * page_size);
  expected_reads.push_back(first_read_addr + 7 * page_size);

  ASSERT_FALSE(ScudoAddCauseProtosIfNeeded(&tombstone, &unwinder, info));
  ASSERT_THAT(memory->test_read_addrs(), testing::UnorderedElementsAreArray(expected_reads));
}
