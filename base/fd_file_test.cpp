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

#include "base/fd_file.h"

#include <gtest/gtest.h>

#include "base/logging.h"

#include "random_access_file_test.h"

using android::base::FdFile;

#ifdef __ANDROID__
static const std::string kTmpDir = "/data/local/tmp/";
#else
static const std::string kTmpDir = "/tmp/";
#endif

class FdFileTest : public RandomAccessFileTest {
 protected:
  FdFileTest() : kGoodPath(kTmpDir + "/some-file.txt") {
  }

  virtual RandomAccessFile* MakeTestFile() {
    FILE* f = tmpfile();
    CHECK(f != nullptr);
    return new FdFile(fileno(f));
  }

  const std::string kGoodPath;
};

TEST_F(FdFileTest, Read) {
  TestRead();
}

TEST_F(FdFileTest, SetLength) {
  TestSetLength();
}

TEST_F(FdFileTest, Write) {
  TestWrite();
}

TEST_F(FdFileTest, UnopenedFile) {
  FdFile file;
  EXPECT_EQ(-1, file.fd());
  EXPECT_FALSE(file.is_opened());
  EXPECT_TRUE(file.file_path().empty());
}

TEST_F(FdFileTest, OpenClose) {
  FdFile file;
  ASSERT_TRUE(file.Open(kGoodPath, O_CREAT | O_WRONLY));
  EXPECT_GE(file.fd(), 0);
  EXPECT_TRUE(file.is_opened());
  EXPECT_TRUE(file.Close());
  EXPECT_EQ(-1, file.fd());
  EXPECT_FALSE(file.is_opened());
  EXPECT_TRUE(file.Open(kGoodPath,  O_RDONLY));
  EXPECT_GE(file.fd(), 0);
  EXPECT_TRUE(file.is_opened());
}

TEST_F(FdFileTest, DestructorDoesNotReclose) {
  errno = 0;
  {
    FdFile file;
    ASSERT_TRUE(file.Open(kGoodPath, O_CREAT | O_WRONLY));
    EXPECT_GE(file.fd(), 0);
    EXPECT_TRUE(file.is_opened());
    EXPECT_TRUE(file.Close());
    EXPECT_EQ(0, errno);
  }
  EXPECT_EQ(0, errno);  // Destructor does not attempt to close again.
}
