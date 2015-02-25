/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "transport.h"

#include <gtest/gtest.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>

#include "adb.h"
#include "utils/file.h"

class TemporaryFile {
 public:
  TemporaryFile() {
    init("/data/local/tmp");
    if (fd == -1) {
      init("/tmp");
    }
  }

  ~TemporaryFile() {
    close(fd);
    unlink(filename);
  }

  int fd;
  char filename[1024];

 private:
  void init(const char* tmp_dir) {
    snprintf(filename, sizeof(filename), "%s/TemporaryFile-XXXXXX", tmp_dir);
    fd = mkstemp(filename);
  }
};

extern "C" int qual_char_is_invalid(char ch);

TEST(transport, kick_transport) {
  atransport t = {};
  // Mutate some member so we can test that the function is run.
  t.kick = [](atransport* trans) { trans->fd = 42; };
  atransport expected = t;
  expected.fd = 42;
  expected.kicked = 1;
  kick_transport(&t);
  ASSERT_EQ(42, t.fd);
  ASSERT_EQ(1, t.kicked);
  ASSERT_EQ(0, memcmp(&expected, &t, sizeof(atransport)));
}

TEST(transport, kick_transport_already_kicked) {
  // Ensure that the transport is not modified if the transport has already been
  // kicked.
  atransport t = {};
  t.kicked = 1;
  t.kick = [](atransport*) { FAIL() << "Kick should not have been called"; };
  atransport expected = t;
  kick_transport(&t);
  ASSERT_EQ(0, memcmp(&expected, &t, sizeof(atransport)));
}

TEST(transport, ReadFdExactly_whole) {
  const char expected[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  ASSERT_TRUE(android::WriteStringToFd(expected, tf.fd)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  // Test reading the whole file.
  char buf[sizeof(expected)] = {};
  ASSERT_TRUE(ReadFdExactly(tf.fd, buf, sizeof(buf) - 1)) << strerror(errno);
  EXPECT_STREQ(expected, buf);
}

TEST(transport, ReadFdExactly_eof) {
  const char expected[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  ASSERT_TRUE(android::WriteStringToFd(expected, tf.fd)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  // Test that not having enough data will fail.
  char buf[sizeof(expected) + 1] = {};
  ASSERT_FALSE(ReadFdExactly(tf.fd, buf, sizeof(buf)));
  EXPECT_EQ(0, errno) << strerror(errno);
}

TEST(transport, ReadFdExactly_partial) {
  const char input[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  ASSERT_TRUE(android::WriteStringToFd(input, tf.fd)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  // Test reading a partial file.
  char buf[sizeof(input) - 1] = {};
  ASSERT_TRUE(ReadFdExactly(tf.fd, buf, sizeof(buf) - 1));

  std::string expected(input);
  expected.pop_back();
  EXPECT_STREQ(expected.c_str(), buf);
}

TEST(transport, WriteFdExactly_whole) {
  const char expected[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  // Test writing the whole string to the file.
  ASSERT_TRUE(WriteFdExactly(tf.fd, expected, sizeof(expected)))
    << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  std::string s;
  ASSERT_TRUE(android::ReadFdToString(tf.fd, &s));
  EXPECT_STREQ(expected, s.c_str());
}

TEST(transport, WriteFdExactly_partial) {
  const char buf[] = "Foobar";
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  // Test writing a partial string to the file.
  ASSERT_TRUE(WriteFdExactly(tf.fd, buf, sizeof(buf) - 2)) << strerror(errno);
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));

  std::string expected(buf);
  expected.pop_back();

  std::string s;
  ASSERT_TRUE(android::ReadFdToString(tf.fd, &s));
  EXPECT_EQ(expected, s);
}

// Disabled because the function currently segfaults for a zeroed atransport. I
// want to make sure I understand how this is working at all before I try fixing
// that.
TEST(transport, DISABLED_run_transport_disconnects_zeroed_atransport) {
  atransport t = {};
  run_transport_disconnects(&t);
}
