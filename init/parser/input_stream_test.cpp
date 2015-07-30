// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "input_stream.h"

#include <errno.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "scoped_fd.h"

namespace init {

TEST(InputStream, DataInputStreamBasic) {
  static const char kTestData[] = "Testing";
  DataInputStream stream(kTestData, sizeof(kTestData));
  const void* data = nullptr;
  size_t size = 0;
  ASSERT_TRUE(stream.GetData(&data, &size));
  ASSERT_EQ(sizeof(kTestData), size);
  ASSERT_EQ(0, memcmp(kTestData, data, size));
  // Should be no more data.
  ASSERT_FALSE(stream.GetData(&data, &size));
}

TEST(InputStream, FileInputStreamBasic) {
  static const char kTestPath[] = "/proc/cpuinfo";

  ScopedFd fd_posix;
  ASSERT_TRUE(fd_posix.Open(kTestPath));

  ScopedFd fd_stream;
  ASSERT_TRUE(fd_stream.Open(kTestPath));

  const size_t kBs = FileInputStream::kBlockSize;
  std::vector<char> buf(kBs);

  FileInputStream stream(fd_stream.fd());

  // Assume kTestPath is less than 1GB and
  // bail so we don't get stuck in this loop.
  int loop_count = 1024 * 1024;
  while (loop_count) {
    // Read from both fds
    ssize_t bytes_read = read(fd_posix.fd(), &buf[0], kBs);
    const void* data = nullptr;
    size_t size = 0;
    bool success = stream.GetData(&data, &size);

    // Check results
    if (bytes_read > 0) {
      ASSERT_TRUE(success);
      ASSERT_EQ(static_cast<size_t>(bytes_read), size);
      ASSERT_EQ(0, memcmp(data, &buf[0], bytes_read));
    } else {
      ASSERT_FALSE(success);
      break;
    }
    loop_count--;
  }
  ASSERT_NE(0, loop_count);
}

}  // namespace init
