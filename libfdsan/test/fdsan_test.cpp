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

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "fdsan.h"

using namespace std::chrono_literals;

struct FdsanTest : public ::testing::Test {
  virtual void SetUp() override final {
    // This translation unit will be compiled both with and without libfdsan linked in, so we can
    // test LD_PRELOADed libfdsan as well.
    auto set_error_handler = reinterpret_cast<decltype(&fdsan_set_error_handler)>(
        dlsym(RTLD_DEFAULT, "fdsan_set_error_handler"));
    set_error_handler(
        [](FdsanError* error, void* arg) {
          auto self = static_cast<FdsanTest*>(arg);
          self->errors_.push_back(*error);
        },
        this);
    errors_.clear();
  }

  virtual void TearDown() override final {
    auto reset_error_handler = reinterpret_cast<decltype(&fdsan_reset_error_handler)>(
        dlsym(RTLD_DEFAULT, "fdsan_reset_error_handler"));
    reset_error_handler();
  }

  bool HasReported() const { return !errors_.empty(); }
  std::string ReportedFunction() const { return errors_.front().function_name; }
  int ReportedFd() const { return errors_.front().fd; };

  std::vector<FdsanError> errors_;
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

TEST_F(FdsanTest, thread_stress) {
  static std::atomic<bool> stop = false;
  std::vector<std::thread> threads;
  for (int i = 0; i < 2048; ++i) {
    auto fn = []() {
      while (!stop) {
        int fd = open("/dev/null", O_RDONLY);
        close(fd);
      }
    };
    threads.emplace_back(fn);
  }

  std::this_thread::sleep_for(2s);

  stop = true;
  for (auto& thread : threads) {
    thread.join();
  }
}
