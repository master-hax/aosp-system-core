/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "fdemu.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string>

#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/utf8.h>

using namespace fdemu;

class FdemuTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH + 1];
    DWORD rc = GetTempPath(MAX_PATH + 1, buf);
    CHECK(rc != 0);
    std::wstring u16_dir = buf;
    u16_dir += L"\\adb_fd_test_";
    u16_dir += std::to_wstring(GetCurrentProcessId());

    bool created = CreateDirectoryW(u16_dir.c_str(), nullptr);
    if (!created) {
      if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Make sure that $DIR/nonexistent doesn't exist.
        std::wstring u16_file = u16_dir + L"\\nonexistent";
        bool deleted = DeleteFile(u16_file.c_str());
        CHECK(deleted || GetLastError() == ERROR_FILE_NOT_FOUND);
      }
    }

    std::wstring u16_file = u16_dir + L"\\exists";
    HANDLE file = CreateFileW(u16_file.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(file != INVALID_HANDLE_VALUE);

    DWORD written = 0;
    CHECK(WriteFile(file, "foo", 3, &written, nullptr));
    CHECK(written == 3);
    CloseHandle(file);
    CHECK(android::base::WideToUTF8(u16_dir, &tempdir));
    existing_file = tempdir + "\\exists";

#else

#if defined(__ANDROID__)
    tempdir = "/data/local/tmp/adb_fd_test_XXXXXX";
    CHECK(mkdtemp(&tempdir[0]) != nullptr);
#else
    tempdir = "/tmp/adb_fd_test_XXXXXX";
    CHECK(mkdtemp(&tempdir[0]) != nullptr);
#endif  // defined(__ANDROID__)

    existing_file = tempdir + "/exists";
    int fd = ::open(existing_file.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    CHECK(fd != -1);
    CHECK(android::base::WriteFully(fd, "foo", 3));
    ::close(fd);

#endif  // defined(_WIN32)
  }

  void TearDown() override {}

  std::string tempdir;
  std::string existing_file;
};

TEST_F(FdemuTest, open) {
  FD fd = fdemu::open(existing_file.c_str(), O_RDONLY);
  ASSERT_TRUE(fd != -1) << "open failed: " << strerror(errno);
  char buf[4];
  ASSERT_EQ(3, fdemu::read(fd, buf, sizeof(buf)));
  buf[3] = '\0';
  ASSERT_STREQ("foo", buf);
  ASSERT_EQ(0, fdemu::close(fd));
}

TEST_F(FdemuTest, nonexistent) {
  std::string filename = tempdir + "/nonexistent";
  FD fd = fdemu::open(filename.c_str(), O_RDONLY);
  ASSERT_TRUE(fd == -1);
  ASSERT_EQ(ENOENT, errno);
}

TEST_F(FdemuTest, o_creat) {
  std::string filename = tempdir + "/o_creat";
  FD fd = fdemu::open(filename.c_str(), O_WRONLY | O_CREAT, 0654);
  ASSERT_TRUE(fd != -1) << "open failed: " << strerror(errno);
  ASSERT_EQ(static_cast<ssize_t>(filename.length()),
            fdemu::write(fd, filename.data(), filename.length()));
  ASSERT_EQ(0, fdemu::close(fd));

  fd = fdemu::open(filename.c_str(), O_RDONLY);
  ASSERT_TRUE(fd != -1) << "reopen failed: " << strerror(errno);
  char buf[1024];
  ASSERT_EQ(static_cast<ssize_t>(filename.length()), fdemu::read(fd, buf, sizeof(buf)));
  buf[filename.length()] = '\0';
  ASSERT_STREQ(filename.c_str(), buf);
  ASSERT_EQ(0, fdemu::close(fd));
}
