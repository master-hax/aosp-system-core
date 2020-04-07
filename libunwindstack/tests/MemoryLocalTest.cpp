/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <string.h>
#include <sys/mman.h>

#include <bionic/mte.h>
#include <bionic/mte_kernel.h>

#include <vector>

#include <gtest/gtest.h>

#include "MemoryLocal.h"

namespace unwindstack {

TEST(MemoryLocalTest, read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  MemoryLocal local;

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(local.ReadFully(reinterpret_cast<uint64_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  memset(src.data(), 0x23, 512);
  ASSERT_TRUE(local.ReadFully(reinterpret_cast<uint64_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 512; i++) {
    ASSERT_EQ(0x23U, dst[i]);
  }
  for (size_t i = 512; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }
}

TEST(MemoryLocalTest, read_tag) {
#if defined(__aarch64__) && defined(ANDROID_EXPERIMENTAL_MTE)
  if (!mte_supported()) {
    GTEST_SKIP() << "Requires MTE";
  }

  uintptr_t mapping =
      reinterpret_cast<uintptr_t>(mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE | PROT_MTE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  __asm__ __volatile__(".arch_extension mte; stg %0, [%0]"
                       :
                       : "r"(mapping + (1ULL << 56))
                       : "memory");

  MemoryLocal local;

  EXPECT_EQ(1, local.ReadTag(mapping));
  EXPECT_EQ(0, local.ReadTag(mapping + 16));
#else
  GTEST_SKIP() << "Requires aarch64 + ANDROID_EXPERIMENTAL_MTE";
#endif
}

TEST(MemoryLocalTest, read_illegal) {
  MemoryLocal local;

  std::vector<uint8_t> dst(100);
  ASSERT_FALSE(local.ReadFully(0, dst.data(), 1));
  ASSERT_FALSE(local.ReadFully(0, dst.data(), 100));
}

TEST(MemoryLocalTest, read_overflow) {
  MemoryLocal local;

  // On 32 bit this test doesn't necessarily cause an overflow. The 64 bit
  // version will always go through the overflow check.
  std::vector<uint8_t> dst(100);
  uint64_t value;
  ASSERT_FALSE(local.ReadFully(reinterpret_cast<uint64_t>(&value), dst.data(), SIZE_MAX));
}

TEST(MemoryLocalTest, Read) {
  char* mapping = static_cast<char*>(
      mmap(nullptr, 2 * getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

  ASSERT_NE(MAP_FAILED, mapping);

  mprotect(mapping + getpagesize(), getpagesize(), PROT_NONE);
  memset(mapping + getpagesize() - 1024, 0x4c, 1024);

  MemoryLocal local;

  std::vector<uint8_t> dst(4096);
  ASSERT_EQ(1024U, local.Read(reinterpret_cast<uint64_t>(mapping + getpagesize() - 1024),
                              dst.data(), 4096));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }

  ASSERT_EQ(0, munmap(mapping, 2 * getpagesize()));
}

TEST(MemoryLocalTest, read_hole) {
  void* mapping =
      mmap(nullptr, 3 * 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, mapping);
  memset(mapping, 0xFF, 3 * 4096);
  mprotect(static_cast<char*>(mapping) + 4096, 4096, PROT_NONE);

  MemoryLocal local;
  std::vector<uint8_t> dst(4096 * 3, 0xCC);
  ASSERT_EQ(4096U, local.Read(reinterpret_cast<uintptr_t>(mapping), dst.data(), 4096 * 3));
  for (size_t i = 0; i < 4096; ++i) {
    ASSERT_EQ(0xFF, dst[i]);
  }
  for (size_t i = 4096; i < 4096 * 3; ++i) {
    ASSERT_EQ(0xCC, dst[i]);
  }
  ASSERT_EQ(0, munmap(mapping, 3 * 4096));
}

}  // namespace unwindstack
