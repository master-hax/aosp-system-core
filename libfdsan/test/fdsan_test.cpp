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

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>

#include <gtest/gtest.h>

#include "fdsan.h"

struct FdsanTest : public ::testing::Test {
  virtual void SetUp() override final {
    // This translation unit will be compiled both with and without libfdsan linked in, so we can
    // test LD_PRELOADed libfdsan as well.
    auto set_reporter =
        reinterpret_cast<decltype(&fdsan_set_reporter)>(dlsym(RTLD_DEFAULT, "fdsan_set_reporter"));
    set_reporter(
        [](int fd, const char* function_name, void* arg) {
          auto self = static_cast<FdsanTest*>(arg);
          self->has_reported_ = true;
          self->reported_fd_ = fd;
          self->reported_function_ = function_name;
        },
        this);
  }

  virtual void TearDown() override final {
    auto reset_reporter = reinterpret_cast<decltype(&fdsan_reset_reporter)>(
        dlsym(RTLD_DEFAULT, "fdsan_reset_reporter"));
    reset_reporter();
  }

  bool HasReported() const { return has_reported_; }
  const std::string& ReportedFunction() const { return reported_function_; }
  int ReportedFd() const { return reported_fd_; }

  bool has_reported_ = false;
  int reported_fd_;
  std::string reported_function_;
};

TEST_F(FdsanTest, double_close) {
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  ASSERT_FALSE(HasReported());

  errno = 0;
  close(fd);
  ASSERT_NE(EBADF, errno);
  ASSERT_FALSE(HasReported());

  int second_open = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_EQ(fd, second_open);
  ASSERT_FALSE(HasReported());

  errno = 0;
  close(fd);
  ASSERT_NE(EBADF, errno);
  ASSERT_FALSE(HasReported());

  ASSERT_EQ(-1, close(fd));
  ASSERT_EQ(EBADF, errno);
  ASSERT_TRUE(HasReported());
  ASSERT_EQ("close", ReportedFunction());
  ASSERT_EQ(fd, ReportedFd());
}
