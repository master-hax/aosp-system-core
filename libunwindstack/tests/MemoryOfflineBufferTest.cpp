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

#include <vector>

#include <gtest/gtest.h>

#include <unwindstack/Memory.h>

#include "LogFake.h"

namespace unwindstack {

class MemoryOfflineBufferTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ResetLogs();
    memory_.reset(new MemoryOfflineBuffer(buffer_.data(), kStart, kEnd);
  }

  static void SetUpTestCase() {
    buffer_.resize(kLength);
    for (size_t i = 0; i < kLength; i++) {
      buffer_[i] = i % 189;
    }
  }

  constexpr size_t kLength = 0x2000;
  constexpr uint64_t kStart = 0x1000;
  constexpr uint64_t kEnd = kStart + kLength;
  std::vector<uint8_t> buffer_;
  std::unique_ptr<MemoryOfflineBuffer> memory_;
};

static void VerifyBuffer(uint8_t* buffer, size_t offset, size_t length) {
  for (size_t i = offset; i < offset + length; i++) {
    ASSERT_EQ(i % 189, buffer[i]) << "Failed at byte " << i;
  }
}

TEST_F(MemoryOfflineBufferTest, read_out_of_bounds) {
  std::vector<uint8_t> buffer(1024);
  ASSERT_FALSE(memory_->ReadFully(0, buffer.data(), 1));
  ASSERT_FALSE(memory_->ReadFully(0xfff, buffer.data(), 1));
  ASSERT_FALSE(memory_->ReadFully(0xfff, buffer.data(), 2));
  ASSERT_FALSE(memory_->ReadFully(0x3000, buffer.data(), 1));
  ASSERT_FALSE(memory_->ReadFully(0x3001, buffer.data(), 1));
}

TEST_F(MemoryOfflineBufferTest, read) {
  std::vector<uint8_t> buffer(1024);
  ASSERT_TRUE(memory_->ReadFully(kStart, buffer.data(), 10));
  ASSERT_NO_FATAL_FAILURE(VerifyBuffer(buffer.data(), 0, 10));

  ASSERT_TRUE(memory_->ReadFully(kStart + 555, buffer.data(), 40));
  ASSERT_NO_FATAL_FAILURE(VerifyBuffer(buffer.data(), 555, 40));

  ASSERT_TRUE(memory_->ReadFully(kStart + kLength - 105, buffer.data(), 105));
  ASSERT_NO_FATAL_FAILURE(VerifyBuffer(buffer.data(), kLength - 105, 105));
}

TEST_F(MemoryOfflineBufferTest, read_past_end) {
  std::vector<uint8_t> buffer(1024);
  ASSERT_EQ(100U, memory_->Read(kStart + kLength - 100, buffer.data(), buffer.size()));
  VerifyBuffer(buffer.data(), kLength - 100, 100);
}

}  // namespace unwindstack
