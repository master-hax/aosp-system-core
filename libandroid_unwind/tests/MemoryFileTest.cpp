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

#include <android-base/test_utils.h>
#include <android-base/file.h>
#include <gtest/gtest.h>

#include "Memory.h"

#include "LogFake.h"

class MemoryFileTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
  }
};

TEST_F(MemoryFileTest, memory_file_offset_0) {
  MemoryFileAtOffset memory;

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(android::base::WriteStringToFile("0123456789abcdefghijklmnopqrstuvxyz", tf.path,
                                               0660, getuid(), getgid()));
  ASSERT_TRUE(memory.Init(tf.path, 0));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  ASSERT_STREQ("0123456789", buffer.data());
}

TEST_F(MemoryFileTest, memory_file_offset_non_zero) {
  MemoryFileAtOffset memory;

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(android::base::WriteStringToFile("0123456789abcdefghijklmnopqrstuvxyz", tf.path,
                                               0660, getuid(), getgid()));
  ASSERT_TRUE(memory.Init(tf.path, 10));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  ASSERT_STREQ("abcdefghij", buffer.data());
}

TEST_F(MemoryFileTest, memory_file_offset_non_zero_larger_than_pagesize) {
  MemoryFileAtOffset memory;

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(android::base::WriteStringToFile("0123456789abcdefghijklmnopqrstuvxyz", tf.path,
                                               0660, getuid(), getgid()));
  ASSERT_TRUE(memory.Init(tf.path, 10));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  ASSERT_STREQ("abcdefghij", buffer.data());
}

TEST_F(MemoryFileTest, memory_file_offset_pagesize_aligned) {
  MemoryFileAtOffset memory;

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  size_t pagesize = getpagesize();
  std::string data;
  for (size_t i = 0; i < 2 * pagesize; i++) {
    data += static_cast<char>((i / pagesize) + '0');
    data += static_cast<char>((i % 10) + '0');
  }
  ASSERT_TRUE(android::base::WriteStringToFile(data, tf.path, 0660, getuid(), getgid()));
  ASSERT_TRUE(memory.Init(tf.path, 2 * pagesize));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  std::string expected_str;
  for (size_t i = 0; i < 5; i++) {
    expected_str += '1';
    expected_str += static_cast<char>(((i + pagesize) % 10) + '0');
  }
  ASSERT_STREQ(expected_str.c_str(), buffer.data());
}

TEST_F(MemoryFileTest, memory_file_offset_pagesize_aligned_plus_extra) {
  MemoryFileAtOffset memory;

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  size_t pagesize = getpagesize();
  std::string data;
  for (size_t i = 0; i < 2 * pagesize; i++) {
    data += static_cast<char>((i / pagesize) + '0');
    data += static_cast<char>((i % 10) + '0');
  }
  ASSERT_TRUE(android::base::WriteStringToFile(data, tf.path, 0660, getuid(), getgid()));
  ASSERT_TRUE(memory.Init(tf.path, 2 * pagesize + 10));
  std::vector<char> buffer(11);
  ASSERT_TRUE(memory.Read(0, buffer.data(), 10));
  buffer[10] = '\0';
  std::string expected_str;
  for (size_t i = 0; i < 5; i++) {
    expected_str += '1';
    expected_str += static_cast<char>(((i + pagesize + 5) % 10) + '0');
  }
  ASSERT_STREQ(expected_str.c_str(), buffer.data());
}

TEST_F(MemoryFileTest, memory_file_read_error) {
  MemoryFileAtOffset memory;

  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  std::string data;
  for (size_t i = 0; i < 5000; i++) {
    data += static_cast<char>((i % 10) + '0');
  }
  ASSERT_TRUE(android::base::WriteStringToFile(data, tf.path, 0660, getuid(), getgid()));

  std::vector<char> buffer(100);

  // Read before init.
  ASSERT_FALSE(memory.Read(0, buffer.data(), 10));

  ASSERT_TRUE(memory.Init(tf.path, 0));

  ASSERT_FALSE(memory.Read(10000, buffer.data(), 10));
  ASSERT_FALSE(memory.Read(5000, buffer.data(), 10));
  ASSERT_FALSE(memory.Read(4990, buffer.data(), 11));
  ASSERT_TRUE(memory.Read(4990, buffer.data(), 10));
  ASSERT_FALSE(memory.Read(4999, buffer.data(), 2));
  ASSERT_TRUE(memory.Read(4999, buffer.data(), 1));
}
