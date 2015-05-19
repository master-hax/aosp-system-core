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

#include "base/random_access_file_utils.h"

#include <gtest/gtest.h>

#include "base/fd_file.h"
#include "base/string_file.h"

using android::base::CopyFile;
using android::base::FdFile;
using android::base::StringFile;

class RandomAccessFileUtilsTest : public testing::Test { };

TEST_F(RandomAccessFileUtilsTest, CopyFile) {
  StringFile src;
  StringFile dst;

  const std::string content("hello");
  src.Assign(content);
  ASSERT_EQ(src.ToStringView(), content);
  ASSERT_EQ(dst.ToStringView(), "");

  ASSERT_TRUE(CopyFile(src, &dst));
  ASSERT_EQ(src.ToStringView(), dst.ToStringView());
}

TEST_F(RandomAccessFileUtilsTest, BadSrc) {
  FdFile src(-1);
  StringFile dst;
  ASSERT_FALSE(CopyFile(src, &dst));
}

TEST_F(RandomAccessFileUtilsTest, BadDst) {
  StringFile src;
  FdFile dst(-1);

  // We need some source content to trigger a write.
  // Copying an empty file is a no-op.
  src.Assign("hello");

  ASSERT_FALSE(CopyFile(src, &dst));
}
