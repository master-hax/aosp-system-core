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

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/stringprintf.h>
#include <android-base/test_utils.h>
#include <cutils/android_get_control_file.h>
#include <gtest/gtest.h>

TEST(util, read_file_ENOENT) {
  std::string s("hello");
  errno = 0;
  EXPECT_FALSE(read_file("/proc/does-not-exist", &s));
  EXPECT_EQ(ENOENT, errno);
  EXPECT_EQ("", s); // s was cleared.
}

TEST(util, read_file_success) {
  std::string s("hello");
  EXPECT_TRUE(read_file("/proc/version", &s));
  EXPECT_GT(s.length(), 6U);
  EXPECT_EQ('\n', s[s.length() - 1]);
  s[5] = 0;
  EXPECT_STREQ("Linux", s.c_str());
}

TEST(util, decode_uid) {
  EXPECT_EQ(0U, decode_uid("root"));
  EXPECT_EQ(UINT_MAX, decode_uid("toot"));
  EXPECT_EQ(123U, decode_uid("123"));
}

TEST(util, open_file) {
  // well, assume test running in "su" domain
  std::string path("/dev/kmsg");

  std::string key(ANDROID_FILE_ENV_PREFIX);
  key += path;

  std::for_each(key.begin(), key.end(), [] (char& c) { c = isalnum(c) ? c : '_'; });

  EXPECT_EQ(unsetenv(key.c_str()), 0);

  int fd;

  EXPECT_GE(fd = open_file(path.c_str(), O_RDONLY), 0);
  if (fd < 0) return;
  EXPECT_EQ(android_get_control_file(path.c_str()), -1);
  EXPECT_EQ(setenv(key.c_str(), android::base::StringPrintf("%d", fd).c_str(), true), 0);
  EXPECT_EQ(android_get_control_file(path.c_str()), fd);
  close(fd);
  EXPECT_EQ(android_get_control_file(path.c_str()), -1);
  EXPECT_EQ(unsetenv(key.c_str()), 0);
}
