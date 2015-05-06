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

#include "adb_utils.h"

#include <gtest/gtest.h>

#include <stdlib.h>
#include <string.h>

#include "sysdeps.h"

TEST(adb_utils, directory_exists) {
  ASSERT_TRUE(directory_exists("/proc"));
  ASSERT_FALSE(directory_exists("/proc/self")); // Symbolic link.
  ASSERT_FALSE(directory_exists("/proc/does-not-exist"));
}

TEST(adb_utils, escape_arg) {
  ASSERT_EQ(R"('')", escape_arg(""));

  ASSERT_EQ(R"('abc')", escape_arg("abc"));

  ASSERT_EQ(R"(' abc')", escape_arg(" abc"));
  ASSERT_EQ(R"('\'abc')", escape_arg("'abc"));
  ASSERT_EQ(R"('"abc')", escape_arg("\"abc"));
  ASSERT_EQ(R"('\abc')", escape_arg("\\abc"));
  ASSERT_EQ(R"('(abc')", escape_arg("(abc"));
  ASSERT_EQ(R"(')abc')", escape_arg(")abc"));

  ASSERT_EQ(R"('abc abc')", escape_arg("abc abc"));
  ASSERT_EQ(R"('abc\'abc')", escape_arg("abc'abc"));
  ASSERT_EQ(R"('abc"abc')", escape_arg("abc\"abc"));
  ASSERT_EQ(R"('abc\abc')", escape_arg("abc\\abc"));
  ASSERT_EQ(R"('abc(abc')", escape_arg("abc(abc"));
  ASSERT_EQ(R"('abc)abc')", escape_arg("abc)abc"));

  ASSERT_EQ(R"('abc ')", escape_arg("abc "));
  ASSERT_EQ(R"('abc\'')", escape_arg("abc'"));
  ASSERT_EQ(R"('abc"')", escape_arg("abc\""));
  ASSERT_EQ(R"('abc\')", escape_arg("abc\\"));
  ASSERT_EQ(R"('abc(')", escape_arg("abc("));
  ASSERT_EQ(R"('abc)')", escape_arg("abc)"));
}

class adb_utils_fixture : public ::testing::Test {
 protected:
  virtual void SetUp() {
    tmp_exists_ = false;
    char *temp_pattern = strdup("/tmp/adb-util-test-mkdirs.XXXXXX");
    ASSERT_NE(nullptr, temp_pattern) << "Failed to allocate directory name.";
    char *temp = mkdtemp(temp_pattern);
    if (temp == nullptr)
      free(temp_pattern);
    else
      tmp_exists_ = true;
    ASSERT_NE(nullptr, temp) << "Failed to create test directory.";
    path_ = temp;
    free(temp_pattern);
  }

  virtual void TearDown() {
    if(tmp_exists_) {
      adb_unlink((path_+"/file").c_str());
      rmdir((path_+"/dir/subdir").c_str());
      rmdir((path_+"/dir").c_str());
      rmdir(path_.c_str());
    }
  }

  std::string& path() { return path_; }

 private:
  std::string path_;
  bool tmp_exists_;
};

TEST_F(adb_utils_fixture, mkdirs) {
  EXPECT_TRUE(mkdirs(path() + "/dir/subdir/file"));
  std::string file = path() + "/file";
  adb_creat(file.c_str(), 0600);
  EXPECT_FALSE(mkdirs(file + "/subdir/"));
}
