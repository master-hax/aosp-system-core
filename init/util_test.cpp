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

#include <errno.h>
#include <fcntl.h>

#include <sys/stat.h>

#include <gtest/gtest.h>

TEST(util, read_file_ENOENT) {
  std::string s("hello");
  errno = 0;
  EXPECT_FALSE(read_file("/proc/does-not-exist", &s));
  EXPECT_EQ(ENOENT, errno);
  EXPECT_EQ("", s); // s was cleared.
}

TEST(util, read_file_group_world_writeable) {
    std::string s("hello");
    errno = 0;
    // -rw-rw-rw- 1 shell shell 0 1970-01-01 05:06 /proc/self/timerslack_ns
    EXPECT_FALSE(read_file("/proc/self/timerslack_ns", &s));
    EXPECT_EQ(0, errno);
    EXPECT_EQ("", s);  // s was cleared.
}

TEST(util, read_file_symbol_link) {
    std::string s("hello");
    errno = 0;
    // lrwxrwxrwx 1 root root 13 1970-01-01 00:00 charger -> /sbin/healthd
    EXPECT_FALSE(read_file("/charger", &s));
    EXPECT_EQ(ELOOP, errno);
    EXPECT_EQ("", s);  // s was cleared.
}

TEST(util, read_file_success) {
  std::string s("hello");
  EXPECT_TRUE(read_file("/proc/version", &s));
  EXPECT_GT(s.length(), 6U);
  EXPECT_EQ('\n', s[s.length() - 1]);
  s[5] = 0;
  EXPECT_STREQ("Linux", s.c_str());
}

TEST(util, write_file_not_exist) {
    std::string s("hello");
    std::string s2("hello");
    char path[] = "/data/local/tmp/does-not-exist";
    EXPECT_TRUE(write_file(path, s.c_str()));
    EXPECT_TRUE(read_file(path, &s2));
    EXPECT_EQ(s, s2);
    struct stat sb;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    EXPECT_NE(-1, fd);
    EXPECT_EQ(0, fstat(fd, &sb));
    EXPECT_NE(0u, sb.st_mode & S_IRUSR);
    EXPECT_NE(0u, sb.st_mode & S_IWUSR);
    EXPECT_EQ(0u, sb.st_mode & S_IXUSR);
    EXPECT_EQ(0u, sb.st_mode & S_IRGRP);
    EXPECT_EQ(0u, sb.st_mode & S_IWGRP);
    EXPECT_EQ(0u, sb.st_mode & S_IXGRP);
    EXPECT_EQ(0u, sb.st_mode & S_IROTH);
    EXPECT_EQ(0u, sb.st_mode & S_IWOTH);
    EXPECT_EQ(0u, sb.st_mode & S_IXOTH);
    EXPECT_EQ(0, unlink(path));
}

TEST(util, write_file_exist) {
    std::string s2("");
    char path[] = "/data/local/tmp/does-exist";
    EXPECT_TRUE(write_file(path, "1hello1"));
    EXPECT_TRUE(read_file(path, &s2));
    EXPECT_STREQ("1hello1", s2.c_str());
    EXPECT_TRUE(write_file(path, "2hello2"));
    EXPECT_TRUE(read_file(path, &s2));
    EXPECT_STREQ("2hello2", s2.c_str());
    EXPECT_EQ(0, unlink(path));
}

TEST(util, decode_uid) {
  EXPECT_EQ(0U, decode_uid("root"));
  EXPECT_EQ(UINT_MAX, decode_uid("toot"));
  EXPECT_EQ(123U, decode_uid("123"));
}
