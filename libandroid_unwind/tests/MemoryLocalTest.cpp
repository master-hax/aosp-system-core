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

#include "LogFake.h"

class MemoryLocalTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
  }
};

#include <errno.h>
#include <string.h>


TEST_F(MemoryLocalTest, read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  MemoryMapLocal local;
  ASSERT_TRUE(local.Init());

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(local.Read(reinterpret_cast<uintptr_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  memset(src.data(), 0x23, 512);
  ASSERT_TRUE(local.Read(reinterpret_cast<uintptr_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 512; i++) {
    ASSERT_EQ(0x23U, dst[i]);
  }
  for (size_t i = 512; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }
}

TEST_F(MemoryLocalTest, read_illegal) {
  MemoryMapLocal local;
  ASSERT_TRUE(local.Init());

  std::vector<uint8_t> dst(100);
  ASSERT_FALSE(local.Read(0, dst.data(), 1));
  ASSERT_FALSE(local.Read(0, dst.data(), 100));
}
