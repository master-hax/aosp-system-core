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

#include <errno.h>

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "base/logging.h"

using android::base::FdFile;

#ifdef __ANDROID__
static const std::string kGoodPath = "/data/local/tmp/some-file.txt";
#else
static const std::string kGoodPath = "/tmp/some-file.txt";
#endif

// TODO(enh): ReadString (and WriteString) might be generally useful.
static bool ReadString(FdFile* f, std::string* s) {
  s->clear();
  char buf[256];
  int64_t n = 0;
  int64_t offset = 0;
  while ((n = f->Read(buf, sizeof(buf), offset)) > 0) {
    s->append(buf, n);
    offset += n;
  }
  return n != -1;
}

FdFile* MakeTestFile() {
  FILE* f = tmpfile();
  CHECK(f != NULL);
  return new FdFile(fileno(f));
}

static void TestReadContent(const std::string& content, FdFile* file) {
  const int buf_size = content.size() + 10;
  std::unique_ptr<char[]> buf(new char[buf_size]);
  // Can't read from a negative offset.
  ASSERT_EQ(-EINVAL, file->Read(buf.get(), 0, -123));

  // Reading too much gets us just what's in the file.
  ASSERT_EQ(static_cast<ssize_t>(content.size()),
            file->Read(buf.get(), buf_size, 0));
  ASSERT_EQ(std::string(buf.get(), content.size()), content);

  // We only get as much as we ask for.
  const ssize_t short_request = 2;
  ASSERT_LT(short_request, static_cast<ssize_t>(content.size()));
  ASSERT_EQ(short_request, file->Read(buf.get(), short_request, 0));
  ASSERT_EQ(std::string(buf.get(), short_request),
            content.substr(0, short_request));

  // We don't have to start at the beginning.
  const int non_zero_offset = 2;
  ASSERT_GT(non_zero_offset, 0);
  ASSERT_EQ(short_request,
            file->Read(buf.get(), short_request, non_zero_offset));
  ASSERT_EQ(std::string(buf.get(), short_request),
            content.substr(non_zero_offset, short_request));

  // Reading past the end gets us nothing.
  ASSERT_EQ(0, file->Read(buf.get(), buf_size, file->GetLength()));
  ASSERT_EQ(0, file->Read(buf.get(), buf_size, file->GetLength() + 1));
}

TEST(FdFileTest, Read) {
  char buf[256];
  std::unique_ptr<FdFile> file(MakeTestFile());

  // Reading from the start of an empty file gets you zero bytes, however many
  // you ask for.
  ASSERT_EQ(0, file->Read(buf, 0, 0));
  ASSERT_EQ(0, file->Read(buf, 123, 0));

  const std::string content("hello");
  ASSERT_EQ(static_cast<ssize_t>(content.size()),
            file->Write(content.data(), content.size(), 0));

  TestReadContent(content, file.get());
}

TEST(FdFileTest, SetLength) {
  const std::string content("hello");
  std::unique_ptr<FdFile> file(MakeTestFile());
  ASSERT_EQ(static_cast<ssize_t>(content.size()),
            file->Write(content.data(), content.size(), 0));
  ASSERT_EQ(static_cast<ssize_t>(content.size()), file->GetLength());

  // Can't give a file a negative length.
  ASSERT_EQ(-EINVAL, file->SetLength(-123));

  // Can truncate the file.
  int new_length = 2;
  ASSERT_EQ(0, file->SetLength(new_length));
  ASSERT_EQ(new_length, file->GetLength());
  std::string new_content;
  ASSERT_TRUE(ReadString(file.get(), &new_content));
  ASSERT_EQ(content.substr(0, 2), new_content);

  // Expanding the file appends zero bytes.
  new_length = file->GetLength() + 1;
  ASSERT_EQ(0, file->SetLength(new_length));
  ASSERT_EQ(new_length, file->GetLength());
  ASSERT_TRUE(ReadString(file.get(), &new_content));
  ASSERT_EQ('\0', new_content[new_length - 1]);
}

TEST(FdFileTest, Write) {
  const std::string content("hello");
  std::unique_ptr<FdFile> file(MakeTestFile());

  // Can't write to a negative offset.
  ASSERT_EQ(-EINVAL, file->Write(content.data(), 0, -123));

  // Writing zero bytes of data is a no-op.
  ASSERT_EQ(0, file->Write(content.data(), 0, 0));
  ASSERT_EQ(0, file->GetLength());

  // We can write data.
  ASSERT_EQ(static_cast<ssize_t>(content.size()),
            file->Write(content.data(), content.size(), 0));
  ASSERT_EQ(static_cast<ssize_t>(content.size()), file->GetLength());
  std::string new_content;
  ASSERT_TRUE(ReadString(file.get(), &new_content));
  ASSERT_EQ(new_content, content);

  // We can read it back.
  char buf[256];
  ASSERT_EQ(static_cast<ssize_t>(content.size()),
            file->Read(buf, sizeof(buf), 0));
  ASSERT_EQ(std::string(buf, content.size()), content);

  // We can append data past the end.
  ASSERT_EQ(static_cast<ssize_t>(content.size()),
            file->Write(content.data(), content.size(), file->GetLength() + 1));
  off_t new_length = 2 * content.size() + 1;
  ASSERT_EQ(file->GetLength(), new_length);
  ASSERT_TRUE(ReadString(file.get(), &new_content));
  ASSERT_EQ(std::string("hello\0hello", new_length), new_content);
}

TEST(FdFileTest, UnopenedFile) {
  FdFile file;
  EXPECT_EQ(-1, file.fd());
  EXPECT_FALSE(file.is_opened());
  EXPECT_TRUE(file.file_path().empty());
}

TEST(FdFileTest, OpenClose) {
  FdFile file;
  ASSERT_TRUE(file.Open(kGoodPath, O_CREAT | O_WRONLY));
  EXPECT_GE(file.fd(), 0);
  EXPECT_TRUE(file.is_opened());
  EXPECT_EQ(0, file.Close());
  EXPECT_EQ(-1, file.fd());
  EXPECT_FALSE(file.is_opened());
  EXPECT_TRUE(file.Open(kGoodPath, O_RDONLY));
  EXPECT_GE(file.fd(), 0);
  EXPECT_TRUE(file.is_opened());
}

TEST(FdFileTest, NoErrorOnMultipleClose) {
  errno = 0;
  {
    FdFile file;
    ASSERT_TRUE(file.Open(kGoodPath, O_CREAT | O_WRONLY));
    EXPECT_GE(file.fd(), 0);
    EXPECT_TRUE(file.is_opened());
    EXPECT_EQ(0, file.Close());
    EXPECT_EQ(0, errno);
    EXPECT_EQ(0, file.Close());  // Second Close() is a no-op.
    EXPECT_EQ(0, errno);
  }
  EXPECT_EQ(0, errno);  // Destructor does not attempt to close again.
}
