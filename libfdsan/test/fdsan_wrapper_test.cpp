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
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>

#include "fdsan.h"

using android::base::unique_fd;

struct FdsanWrapperTest : public ::testing::Test {
  virtual void SetUp() override final {
    // Get the next available fd, and clear its history.
    next_fd_ = NextFd();
    ClearHistory(next_fd_);
  }

  int NextFd() {
    int next_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (next_fd == -1) {
      err(1, "failed to open /dev/null");
    }
    close(next_fd);
    return next_fd;
  }

  virtual void TearDown() override final {}

  static void ClearHistory(int fd) {
    static auto clear_history = reinterpret_cast<decltype(&fdsan_clear_history)>(
        dlsym(RTLD_DEFAULT, "fdsan_clear_history"));
    clear_history(fd);
  }

  static void IterateHistory(int fd, std::function<bool(int, const FdEvent&)> fn) {
    static auto iterate_history = reinterpret_cast<decltype(&fdsan_iterate_history)>(
        dlsym(RTLD_DEFAULT, "fdsan_iterate_history"));
    iterate_history(fd,
                    [](int fd, const FdEvent& event, void* arg) {
                      auto f = reinterpret_cast<decltype(&fn)>(arg);
                      return (*f)(fd, event);
                    },
                    &fn);
  }

  static std::string GetFdCreator(int fd) {
    std::string result;
    IterateHistory(fd, [&result](int fd, const FdEvent& event) {
      if (event.type == FdEventType::Create || event.type == FdEventType::Dup) {
        if (!result.empty()) {
          errx(1, "multiple creators for fd %d", fd);
        }
        result = event.function;
        return false;
      }
      return true;
    });
    return result;
  }

  int next_fd_;
};

TEST_F(FdsanWrapperTest, dup) {
  unique_fd fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  int expected_dup = NextFd();
  ClearHistory(expected_dup);
  unique_fd duped(dup(fd.get()));
  ASSERT_EQ(expected_dup, duped.get());
  ASSERT_EQ("dup", GetFdCreator(duped.get()));
}

TEST_F(FdsanWrapperTest, dup2) {
  unique_fd fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  int expected_dup = NextFd();
  ClearHistory(expected_dup);
  unique_fd duped(dup2(fd.get(), expected_dup));
  ASSERT_EQ(expected_dup, duped.get());
  ASSERT_EQ("dup2", GetFdCreator(duped.get()));
}

TEST_F(FdsanWrapperTest, dup3) {
  unique_fd fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  int expected_dup = NextFd();
  ClearHistory(expected_dup);
  unique_fd duped(dup3(fd.get(), expected_dup, 0));
  ASSERT_EQ(expected_dup, duped.get());
  ASSERT_EQ("dup3", GetFdCreator(duped.get()));
}

TEST_F(FdsanWrapperTest, fcntl) {
  unique_fd fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  int expected_dup = NextFd();
  ClearHistory(expected_dup);
  unique_fd duped(fcntl(fd.get(), F_DUPFD, expected_dup));
  ASSERT_EQ(expected_dup, duped.get());
  ASSERT_EQ("fcntl", GetFdCreator(duped.get()));
}

TEST_F(FdsanWrapperTest, open) {
  unique_fd fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("open", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, open64) {
  unique_fd fd(open64("/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("open64", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, openat) {
  unique_fd fd(openat(AT_FDCWD, "/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("openat", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, openat64) {
  unique_fd fd(openat64(AT_FDCWD, "/dev/null", O_WRONLY | O_CLOEXEC));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("openat64", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, creat) {
  unique_fd fd(creat("/data/local/tmp/fdsan_test_tmp", 0700));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("creat", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, creat64) {
  unique_fd fd(creat64("/data/local/tmp/fdsan_test_tmp", 0700));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("creat64", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, mkstemp) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkstemp(buf));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkstemp", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkstemp64) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkstemp64(buf));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkstemp64", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkostemp) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkostemp(buf, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkostemp", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkostemp64) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkostemp64(buf, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkostemp64", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkstemps) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkstemps(buf, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkstemps", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkstemps64) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkstemps64(buf, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkstemps64", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkostemps) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkostemps(buf, 0, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkostemps", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, mkostemps64) {
  char buf[] = "/data/local/tmp/fdsan_test_XXXXXX";
  unique_fd fd(mkostemps64(buf, 0, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("mkostemps64", GetFdCreator(fd.get()));
  ASSERT_EQ(0, unlink(buf));
}

TEST_F(FdsanWrapperTest, socket) {
  unique_fd fd(socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("socket", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, accept) {
  // TODO
}

TEST_F(FdsanWrapperTest, accept4) {
  // TODO
}

TEST_F(FdsanWrapperTest, eventfd) {
  unique_fd fd(eventfd(0, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("eventfd", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, epoll_create) {
  unique_fd fd(epoll_create(1));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("epoll_create", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, epoll_create1) {
  unique_fd fd(epoll_create1(0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("epoll_create1", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, inotify_init) {
  unique_fd fd(inotify_init());
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("inotify_init", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, inotify_init1) {
  unique_fd fd(inotify_init1(0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("inotify_init1", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, signalfd) {
  sigset_t set;
  sigfillset(&set);

  // TODO: Test with fd != -1 as well, once fdsan checks that.
  unique_fd fd(signalfd(-1, &set, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("signalfd", GetFdCreator(fd.get()));
}

TEST_F(FdsanWrapperTest, timerfd_create) {
  unique_fd fd(timerfd_create(CLOCK_REALTIME, 0));
  ASSERT_EQ(next_fd_, fd.get());
  ASSERT_EQ("timerfd_create", GetFdCreator(fd.get()));
}
