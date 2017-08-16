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

#include <inttypes.h>
#include <sys/mman.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include <unwindstack/Maps.h>

namespace unwindstack {

TEST(MapsTest, parse_permissions) {
  BufferMaps maps(
      "1000-2000 ---- 00000000 00:00 0\n"
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
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(PROT_READ, it->flags);
  ASSERT_EQ(0x2000U, it->start);
  ASSERT_EQ(0x3000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(PROT_WRITE, it->flags);
  ASSERT_EQ(0x3000U, it->start);
  ASSERT_EQ(0x4000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(PROT_EXEC, it->flags);
  ASSERT_EQ(0x4000U, it->start);
  ASSERT_EQ(0x5000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, it->flags);
  ASSERT_EQ(0x5000U, it->start);
  ASSERT_EQ(0x6000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(it, maps.end());
}

TEST(MapsTest, parse_name) {
  BufferMaps maps(
      "720b29b000-720b29e000 rw-p 00000000 00:00 0\n"
      "720b29e000-720b29f000 rw-p 00000000 00:00 0 /system/lib/fake.so\n"
      "720b29f000-720b2a0000 rw-p 00000000 00:00 0");

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(3U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ("", it->name);
  ASSERT_EQ(0x720b29b000U, it->start);
  ASSERT_EQ(0x720b29e000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ++it;
  ASSERT_EQ("/system/lib/fake.so", it->name);
  ASSERT_EQ(0x720b29e000U, it->start);
  ASSERT_EQ(0x720b29f000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ++it;
  ASSERT_EQ("", it->name);
  ASSERT_EQ(0x720b29f000U, it->start);
  ASSERT_EQ(0x720b2a0000U, it->end);
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ++it;
  ASSERT_EQ(it, maps.end());
}

TEST(MapsTest, parse_offset) {
  BufferMaps maps(
      "a000-e000 rw-p 00000000 00:00 0 /system/lib/fake.so\n"
      "e000-f000 rw-p 00a12345 00:00 0 /system/lib/fake.so\n");

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(2U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(0U, it->offset);
  ASSERT_EQ(0xa000U, it->start);
  ASSERT_EQ(0xe000U, it->end);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ASSERT_EQ("/system/lib/fake.so", it->name);
  ++it;
  ASSERT_EQ(0xa12345U, it->offset);
  ASSERT_EQ(0xe000U, it->start);
  ASSERT_EQ(0xf000U, it->end);
  ASSERT_EQ(PROT_READ | PROT_WRITE, it->flags);
  ASSERT_EQ("/system/lib/fake.so", it->name);
  ++it;
  ASSERT_EQ(maps.end(), it);
}

TEST(MapsTest, device) {
  BufferMaps maps(
      "a000-e000 rw-p 00000000 00:00 0 /dev/\n"
      "f000-f100 rw-p 00000000 00:00 0 /dev/does_not_exist\n"
      "f100-f200 rw-p 00000000 00:00 0 /dev/ashmem/does_not_exist\n"
      "f200-f300 rw-p 00000000 00:00 0 /devsomething/does_not_exist\n");

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(4U, maps.Total());
  auto it = maps.begin();
  ASSERT_TRUE(it->flags & 0x8000);
  ASSERT_EQ("/dev/", it->name);
  ++it;
  ASSERT_TRUE(it->flags & 0x8000);
  ASSERT_EQ("/dev/does_not_exist", it->name);
  ++it;
  ASSERT_FALSE(it->flags & 0x8000);
  ASSERT_EQ("/dev/ashmem/does_not_exist", it->name);
  ++it;
  ASSERT_FALSE(it->flags & 0x8000);
  ASSERT_EQ("/devsomething/does_not_exist", it->name);
}

TEST(MapsTest, file_smoke) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(
      android::base::WriteStringToFile("720b29b000-720b29e000 r-xp a0000000 00:00 0   /fake.so\n"
                                       "720b2b0000-720b2e0000 r-xp b0000000 00:00 0   /fake2.so\n"
                                       "720b2e0000-720b2f0000 r-xp c0000000 00:00 0   /fake3.so\n",
                                       tf.path, 0660, getuid(), getgid()));

  FileMaps maps(tf.path);

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(3U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(0x720b29b000U, it->start);
  ASSERT_EQ(0x720b29e000U, it->end);
  ASSERT_EQ(0xa0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ("/fake.so", it->name);
  ++it;
  ASSERT_EQ(0x720b2b0000U, it->start);
  ASSERT_EQ(0x720b2e0000U, it->end);
  ASSERT_EQ(0xb0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ("/fake2.so", it->name);
  ++it;
  ASSERT_EQ(0x720b2e0000U, it->start);
  ASSERT_EQ(0x720b2f0000U, it->end);
  ASSERT_EQ(0xc0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ("/fake3.so", it->name);
  ++it;
  ASSERT_EQ(it, maps.end());
}

static void VerifyLine(std::string line, MapInfo* info) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(android::base::WriteStringToFile(line, tf.path, 0660, getuid(), getgid()));

  FileMaps maps(tf.path);

  if (info == nullptr) {
    ASSERT_FALSE(maps.Parse());
  } else {
    ASSERT_TRUE(maps.Parse());
    MapInfo* element = maps.Get(0);
    ASSERT_TRUE(element != nullptr);
    *info = *element;
  }
}

TEST(MapsTest, file_check_line_parser) {
  MapInfo info;

  VerifyLine("01-02 rwxp 03 04:05 06\n", &info);
  EXPECT_EQ(1U, info.start);
  EXPECT_EQ(2U, info.end);
  EXPECT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, info.flags);
  EXPECT_EQ(3U, info.offset);
  EXPECT_EQ("", info.name);

  VerifyLine("0a-0b ---- 0c 0d:0e 06 /fake/name\n", &info);
  EXPECT_EQ(0xaU, info.start);
  EXPECT_EQ(0xbU, info.end);
  EXPECT_EQ(0U, info.flags);
  EXPECT_EQ(0xcU, info.offset);
  EXPECT_EQ("/fake/name", info.name);

  VerifyLine("01-02   rwxp   03    04:05    06    /fake/name/again\n", &info);
  EXPECT_EQ(1U, info.start);
  EXPECT_EQ(2U, info.end);
  EXPECT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, info.flags);
  EXPECT_EQ(3U, info.offset);
  EXPECT_EQ("/fake/name/again", info.name);

  VerifyLine("x-00 rwxp 00 00:00 0\n", nullptr);
  VerifyLine("00 -00 rwxp 00 00:00 0\n", nullptr);
  VerifyLine("00-x rwxp 00 00:00 0\n", nullptr);
  VerifyLine("00-x rwxp 00 00:00 0\n", nullptr);
  VerifyLine("00-00x rwxp 00 00:00 0\n", nullptr);
  VerifyLine("00-00 rwxp0 00 00:00 0\n", nullptr);
  VerifyLine("00-00 rwxp0 00 00:00 0\n", nullptr);
  VerifyLine("00-00 rwp 00 00:00 0\n", nullptr);
  VerifyLine("00-00 rwxp 0000:00 0\n", nullptr);
  VerifyLine("00-00 rwxp 00 00 :00 0\n", nullptr);
  VerifyLine("00-00 rwxp 00 00: 00 0\n", nullptr);
  VerifyLine("00-00 rwxp 00 00:000\n", nullptr);
  VerifyLine("00-00 rwxp 00 00:00 0/fake\n", nullptr);
}

TEST(MapsTest, file_no_map_name) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(
      android::base::WriteStringToFile("720b29b000-720b29e000 r-xp a0000000 00:00 0\n"
                                       "720b2b0000-720b2e0000 r-xp b0000000 00:00 0   /fake2.so\n"
                                       "720b2e0000-720b2f0000 r-xp c0000000 00:00 0 \n",
                                       tf.path, 0660, getuid(), getgid()));

  FileMaps maps(tf.path);

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(3U, maps.Total());
  auto it = maps.begin();
  ASSERT_EQ(0x720b29b000U, it->start);
  ASSERT_EQ(0x720b29e000U, it->end);
  ASSERT_EQ(0xa0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(0x720b2b0000U, it->start);
  ASSERT_EQ(0x720b2e0000U, it->end);
  ASSERT_EQ(0xb0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ("/fake2.so", it->name);
  ++it;
  ASSERT_EQ(0x720b2e0000U, it->start);
  ASSERT_EQ(0x720b2f0000U, it->end);
  ASSERT_EQ(0xc0000000U, it->offset);
  ASSERT_EQ(PROT_READ | PROT_EXEC, it->flags);
  ASSERT_EQ("", it->name);
  ++it;
  ASSERT_EQ(it, maps.end());
}

// Verify that a file that crosses a buffer is parsed correctly.
static std::string CreateEntry(size_t index) {
  return android::base::StringPrintf("%08zx-%08zx rwxp 0000 00:00 0\n", index * 4096,
                                     (index + 1) * 4096);
}

TEST(MapsTest, file_buffer_cross) {
  constexpr size_t kBufferSize = 2048;
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  // Compute how many to add in the first buffer.
  size_t entry_len = CreateEntry(0).size();
  size_t index;
  std::string file_data;
  for (index = 0; index < kBufferSize / entry_len; index++) {
    file_data += CreateEntry(index);
  }
  // Add a long name to make sure that the first buffer does not contain a
  // complete line.
  // Remove the last newline.
  size_t extra = 0;
  size_t leftover = kBufferSize % entry_len;
  size_t overlap1_entry = index;
  if (leftover == 0) {
    // Exact match, add a long name to cross over the value.
    file_data.erase(file_data.size() - 1);
    std::string name(" /fake/name/is/long/on/purpose\n");
    file_data += name;
    extra = entry_len + name.size() - 1;
  } else {
    overlap1_entry++;
  }
  // Compute how many need to go in to hit the buffer boundary exactly.
  size_t bytes_left_in_buffer = kBufferSize - extra;
  size_t entries_to_add = bytes_left_in_buffer / entry_len + index;
  for (; index < entries_to_add; index++) {
    file_data += CreateEntry(index);
  }

  // Now figure out how many bytes to add to get exactly to the buffer boundary.
  leftover = bytes_left_in_buffer % entry_len;
  if (leftover != 0) {
    file_data.erase(file_data.size() - 1);
    file_data += ' ';
    for (size_t i = 1; i < leftover; i++) {
      file_data += 'x';
    }
    file_data += '\n';
  }
  size_t overlap2_entry = index;

  // Now add a few entries on the next page.
  for (; index < overlap2_entry + 10; index++) {
    file_data += CreateEntry(index);
  }

  ASSERT_TRUE(android::base::WriteStringToFile(file_data, tf.path, 0660, getuid(), getgid()));

  FileMaps maps(tf.path);
  ASSERT_TRUE(maps.Parse());
  EXPECT_EQ(index, maps.Total());
  // Check the first buffer overlap entries.
  MapInfo* info = maps.Get(overlap1_entry - 1);
  ASSERT_TRUE(info != nullptr);
  EXPECT_EQ((overlap1_entry - 1) * 4096, info->start);
  EXPECT_EQ(overlap1_entry * 4096, info->end);
  info = maps.Get(overlap1_entry);
  EXPECT_EQ(overlap1_entry * 4096, info->start);
  EXPECT_EQ((overlap1_entry + 1) * 4096, info->end);

  // Check the second buffer overlap entries.
  info = maps.Get(overlap2_entry - 1);
  ASSERT_TRUE(info != nullptr);
  EXPECT_EQ((overlap2_entry - 1) * 4096, info->start);
  EXPECT_EQ(overlap2_entry * 4096, info->end);
  info = maps.Get(overlap2_entry);
  EXPECT_EQ(overlap2_entry * 4096, info->start);
  EXPECT_EQ((overlap2_entry + 1) * 4096, info->end);
}

TEST(MapsTest, file_should_fail) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_TRUE(android::base::WriteStringToFile(
      "7ffff7dda000-7ffff7dfd7ffff7ff3000-7ffff7ff4000 ---p 0000f000 fc:02 44171565\n", tf.path,
      0660, getuid(), getgid()));

  FileMaps maps(tf.path);

  ASSERT_FALSE(maps.Parse());
}

// Create a maps file that is extremely large.
TEST(MapsTest, large_file) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  std::string file_data;
  uint64_t start = 0x700000;
  for (size_t i = 0; i < 5000; i++) {
    file_data +=
        android::base::StringPrintf("%" PRIx64 "-%" PRIx64 " r-xp 1000 00:0 0 /fake%zu.so\n",
                                    start + i * 4096, start + (i + 1) * 4096, i);
  }

  ASSERT_TRUE(android::base::WriteStringToFile(file_data, tf.path, 0660, getuid(), getgid()));

  FileMaps maps(tf.path);

  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(5000U, maps.Total());
  for (size_t i = 0; i < 5000; i++) {
    MapInfo* info = maps.Get(i);
    ASSERT_EQ(start + i * 4096, info->start) << "Failed at map " + std::to_string(i);
    ASSERT_EQ(start + (i + 1) * 4096, info->end) << "Failed at map " + std::to_string(i);
    std::string name = "/fake" + std::to_string(i) + ".so";
    ASSERT_EQ(name, info->name) << "Failed at map " + std::to_string(i);
  }
}

TEST(MapsTest, find) {
  BufferMaps maps(
      "1000-2000 r--p 00000010 00:00 0 /system/lib/fake1.so\n"
      "3000-4000 -w-p 00000020 00:00 0 /system/lib/fake2.so\n"
      "6000-8000 --xp 00000030 00:00 0 /system/lib/fake3.so\n"
      "a000-b000 rw-p 00000040 00:00 0 /system/lib/fake4.so\n"
      "e000-f000 rwxp 00000050 00:00 0 /system/lib/fake5.so\n");
  ASSERT_TRUE(maps.Parse());
  ASSERT_EQ(5U, maps.Total());

  ASSERT_TRUE(maps.Find(0x500) == nullptr);
  ASSERT_TRUE(maps.Find(0x2000) == nullptr);
  ASSERT_TRUE(maps.Find(0x5010) == nullptr);
  ASSERT_TRUE(maps.Find(0x9a00) == nullptr);
  ASSERT_TRUE(maps.Find(0xf000) == nullptr);
  ASSERT_TRUE(maps.Find(0xf010) == nullptr);

  MapInfo* info = maps.Find(0x1000);
  ASSERT_TRUE(info != nullptr);
  ASSERT_EQ(0x1000U, info->start);
  ASSERT_EQ(0x2000U, info->end);
  ASSERT_EQ(0x10U, info->offset);
  ASSERT_EQ(PROT_READ, info->flags);
  ASSERT_EQ("/system/lib/fake1.so", info->name);

  info = maps.Find(0x3020);
  ASSERT_TRUE(info != nullptr);
  ASSERT_EQ(0x3000U, info->start);
  ASSERT_EQ(0x4000U, info->end);
  ASSERT_EQ(0x20U, info->offset);
  ASSERT_EQ(PROT_WRITE, info->flags);
  ASSERT_EQ("/system/lib/fake2.so", info->name);

  info = maps.Find(0x6020);
  ASSERT_TRUE(info != nullptr);
  ASSERT_EQ(0x6000U, info->start);
  ASSERT_EQ(0x8000U, info->end);
  ASSERT_EQ(0x30U, info->offset);
  ASSERT_EQ(PROT_EXEC, info->flags);
  ASSERT_EQ("/system/lib/fake3.so", info->name);

  info = maps.Find(0xafff);
  ASSERT_TRUE(info != nullptr);
  ASSERT_EQ(0xa000U, info->start);
  ASSERT_EQ(0xb000U, info->end);
  ASSERT_EQ(0x40U, info->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE, info->flags);
  ASSERT_EQ("/system/lib/fake4.so", info->name);

  info = maps.Find(0xe500);
  ASSERT_TRUE(info != nullptr);
  ASSERT_EQ(0xe000U, info->start);
  ASSERT_EQ(0xf000U, info->end);
  ASSERT_EQ(0x50U, info->offset);
  ASSERT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, info->flags);
  ASSERT_EQ("/system/lib/fake5.so", info->name);
}

}  // namespace unwindstack
