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

#ifndef _BVB_UNITTEST_UTIL_H
#define _BVB_UNITTEST_UTIL_H

#include <gtest/gtest.h>

// Utility macro to run the command expressed by the printf()-style string
// |command_format| using the system(3) utility function. Will assert unless
// the command exits normally with exit status |expected_exit_status|.
#define EXPECT_COMMAND(expected_exit_status, command_format, ...) do { \
  int rc = system(base::StringPrintf(command_format, ## __VA_ARGS__).c_str()); \
  EXPECT_TRUE(WIFEXITED(rc)); \
  EXPECT_EQ(WEXITSTATUS(rc), expected_exit_status); \
} while (0);

class BaseBVBToolTest : public ::testing::Test {
public:
  BaseBVBToolTest() {}

protected:
  void GenerateBootImage(const std::string& algorithm,
                         const std::string& kernel_cmdline,
                         uint64_t rollback_index,
                         const base::FilePath& key_path,
                         const std::string& additional_options = "") {
    boot_image_path_ = testdir_.Append("boot_brillo.img");
    EXPECT_COMMAND(0,
                   "./bvbtool make_boot_image"
                   " --kernel %s"
                   " --initrd %s"
                   " --device_tree %s"
                   " --kernel_cmdline \"%s\""
                   " --rollback_index %" PRIu64
                   " %s "
                   " --output %s",
                   base::FilePath("test/dummy_kernel.bin").value().c_str(),
                   base::FilePath("test/dummy_initrd.bin").value().c_str(),
                   base::FilePath("test/dummy_device_tree.bin").value().c_str(),
                   kernel_cmdline.c_str(),
                   rollback_index,
                   additional_options.c_str(),
                   boot_image_path_.value().c_str());
    if (algorithm != "") {
      EXPECT_COMMAND(0,
                     "./bvbtool sign_boot_image --key %s"
                     " --image %s --algorithm %s",
                     key_path.value().c_str(),
                     boot_image_path_.value().c_str(),
                     algorithm.c_str());
    }
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(boot_image_path_, &file_size));
    boot_image_.resize(file_size);
    ASSERT_TRUE(base::ReadFile(boot_image_path_,
                               reinterpret_cast<char*>(boot_image_.data()),
                               boot_image_.size()));
  }

  void SetUp() {
    base::FilePath ret;
    char* buf = strdup("/tmp/bvb-refimpl-tests.XXXXXX");
    ASSERT_TRUE(mkdtemp(buf) != nullptr);
    testdir_ = base::FilePath(buf);
    free(buf);
  }

  void TearDown() {
    // Sanity check
    ASSERT_EQ(0U, testdir_.value().find("/tmp/bvb-refimpl-tests"));
    EXPECT_COMMAND(0, "rm -rf %s", testdir_.value().c_str());
  }

  base::FilePath testdir_;
  base::FilePath boot_image_path_;
  std::vector<uint8_t> boot_image_;
};


#endif  /* _BVB_UNITTEST_UTIL_H */
