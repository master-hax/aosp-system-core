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

#include <android-base/unique_fd.h>

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

auto set_close_tag =
    reinterpret_cast<decltype(&fdsan_set_close_tag)>(dlsym(RTLD_DEFAULT, "fdsan_set_close_tag"));
auto close_with_tag =
    reinterpret_cast<decltype(&fdsan_close_with_tag)>(dlsym(RTLD_DEFAULT, "fdsan_close_with_tag"));

TEST_F(FdsanTest, untagged_close) {
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  ASSERT_FALSE(HasReported());
  void* tag = reinterpret_cast<void*>(0xdeadbeef);
  ASSERT_EQ(nullptr, set_close_tag(fd, tag));
  close(fd);
  ASSERT_TRUE(HasReported());
}

TEST_F(FdsanTest, tagged_close) {
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  ASSERT_FALSE(HasReported());
  void* tag = reinterpret_cast<void*>(0xdeadbeef);
  ASSERT_EQ(nullptr, set_close_tag(fd, tag));
  close_with_tag(fd, tag);
  ASSERT_FALSE(HasReported());
}

TEST_F(FdsanTest, tagged_close_untagged) {
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  ASSERT_FALSE(HasReported());
  void* tag = reinterpret_cast<void*>(0xdeadbeef);
  close_with_tag(fd, tag);
  ASSERT_TRUE(HasReported());
}

TEST_F(FdsanTest, tagged_close_fail) {
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  ASSERT_FALSE(HasReported());
  void* tag = reinterpret_cast<void*>(0xdeadbeef);
  ASSERT_EQ(nullptr, set_close_tag(fd, tag));
  close_with_tag(fd, reinterpret_cast<void*>(0xbadc0de));
  ASSERT_TRUE(HasReported());
}

static void* get_close_tag(int fd) {
  void* tag = set_close_tag(fd, nullptr);
  set_close_tag(fd, tag);
  return tag;
}

TEST_F(FdsanTest, tagged_unique_fd) {
  android::base::unique_fd fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_NE(-1, fd.get());
  ASSERT_FALSE(HasReported());

  ASSERT_EQ(&fd, get_close_tag(fd.get()));
  ASSERT_FALSE(HasReported());

  android::base::unique_fd move = std::move(fd);
  ASSERT_EQ(&move, get_close_tag(move.get()));
  ASSERT_FALSE(HasReported());

  close(move.get());
  ASSERT_TRUE(HasReported());
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
