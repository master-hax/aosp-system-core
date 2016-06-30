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

#include <sys/mman.h>

#include <android-base/file.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include "Maps.h"

#include "LogFake.h"

class MapsTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    ResetLogs();
  }
};

TEST_F(MapsTest, parse_permissions) {
  MapsBuffer maps("1000-2000 ---- 00000000 00:00 0\n"
                  "2000-3000 r--- 00000000 00:00 0\n"
                  "3000-4000 -w-- 00000000 00:00 0\n"
                  "4000-5000 --x- 00000000 00:00 0\n"
                  "5000-6000 rwx- 00000000 00:00 0\n");

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(5U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(PROT_NONE, it->flags);
  ASSERT_EQ(0x1000U, it->start);
  ASSERT_EQ(0x2000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(std::string(""), it->name);
  ++it;
  ASSERT_EQ(PROT_READ, it->flags);
  ASSERT_EQ(0x2000U, it->start);
  ASSERT_EQ(0x3000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(std::string(""), it->name);
  ++it;
  ASSERT_EQ(PROT_WRITE, it->flags);
  ASSERT_EQ(0x3000U, it->start);
  ASSERT_EQ(0x4000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(std::string(""), it->name);
  ++it;
  ASSERT_EQ(PROT_EXEC, it->flags);
  ASSERT_EQ(0x4000U, it->start);
  ASSERT_EQ(0x5000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(std::string(""), it->name);
  ++it;
  ASSERT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, it->flags);
  ASSERT_EQ(0x5000U, it->start);
  ASSERT_EQ(0x6000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(std::string(""), it->name);
  ++it;
  ASSERT_EQ(it, maps.end());
}

TEST_F(MapsTest, parse_name) {
  MapsBuffer maps("720b29b000-720b29e000 rw-p 00000000 00:00 0\n"
                  "720b29e000-720b29f000 rw-p 00000000 00:00 0 /system/lib/fake.so\n"
                  "720b29f000-720b2a0000 rw-p 00000000 00:00 0");

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(3U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(std::string(""), it->name);
  ASSERT_EQ(0x720b29b000U, it->start);
  ASSERT_EQ(0x720b29e000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ++it;
  ASSERT_EQ(std::string("/system/lib/fake.so"), it->name);
  ASSERT_EQ(0x720b29e000U, it->start);
  ASSERT_EQ(0x720b29f000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ++it;
  ASSERT_EQ(std::string(""), it->name);
  ASSERT_EQ(0x720b29f000U, it->start);
  ASSERT_EQ(0x720b2a0000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ++it;
  ASSERT_EQ(it, maps.end());
}

TEST_F(MapsTest, parse_offset) {
  MapsBuffer maps("a000-e000 rw-p 00000000 00:00 0 /system/lib/fake.so\n"
                  "e000-f000 rw-p 00a12345 00:00 0 /system/lib/fake.so\n");

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(2U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(0xa000U, it->start);
  ASSERT_EQ(0xe000U, it->end);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ASSERT_EQ(std::string("/system/lib/fake.so"), it->name);
  ++it;
  ASSERT_EQ(0xa12345U, it->offset);
  ASSERT_EQ(0xe000U, it->start);
  ASSERT_EQ(0xf000U, it->end);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ASSERT_EQ(std::string("/system/lib/fake.so"), it->name);
  ++it;
  ASSERT_EQ(maps.end(), it);
}

TEST_F(MapsTest, file_smoke) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(android::base::WriteStringToFile(
      "720b29b000-720b29e000 r-xp a0000000 00:00 0   /fake.so\n"
      "720b2b0000-720b2e0000 r-xp b0000000 00:00 0   /fake2.so\n"
      "720b2e0000-720b2f0000 r-xp c0000000 00:00 0   /fake3.so\n",
      tf.path, 0660, getuid(), getgid()));

  MapsFile maps(tf.path);

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(3U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(0x720b29b000U, it->start);
  ASSERT_EQ(0x720b29e000U, it->end);
  ASSERT_EQ(0xa0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ(std::string("/fake.so"), it->name);
  ++it;
  ASSERT_EQ(0x720b2b0000U, it->start);
  ASSERT_EQ(0x720b2e0000U, it->end);
  ASSERT_EQ(0xb0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ(std::string("/fake2.so"), it->name);
  ++it;
  ASSERT_EQ(0x720b2e0000U, it->start);
  ASSERT_EQ(0x720b2f0000U, it->end);
  ASSERT_EQ(0xc0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ(std::string("/fake3.so"), it->name);
  ++it;
  ASSERT_EQ(it, maps.end());
}

// Need an offline test.

// Need some find tests.
#if 0
TEST_F(MapsTest, parse_permissions) {
}
#endif
