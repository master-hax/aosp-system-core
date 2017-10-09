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

#include <android/dlext.h>
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

static auto clear_history =
    reinterpret_cast<decltype(&fdsan_clear_history)>(dlsym(RTLD_DEFAULT, "fdsan_clear_history"));

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

  static void ClearHistory(int fd) { clear_history(fd); }
  static void ClearAllHistory() { clear_history(-1); }

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

  static std::string GetFdCreator(int fd, bool exclusive = true) {
    std::string result;
    IterateHistory(fd, [&result, exclusive](int fd, const FdEvent& event) {
      if (event.type == FdEventType::Create || event.type == FdEventType::Dup) {
        if (!result.empty() && exclusive) {
          errx(1, "multiple creators for fd %d", fd);
        }
        result = event.function;
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

static void SendFds(int sockfd) {
  unique_fd fds[4];
  for (int i = 0; i < 4; ++i) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
      err(1, "failed to open /dev/null");
    }

    fds[i].reset(fd);
  }

  struct iovec iov;
  iov.iov_base = const_cast<char*>("");
  iov.iov_len = 1;

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  union {
    char buf[4096];
    struct cmsghdr align;
  } cmsg_buf;
  msg.msg_control = cmsg_buf.buf;
  msg.msg_controllen = sizeof(cmsg_buf);

  struct cmsghdr* cmsg_hdr = CMSG_FIRSTHDR(&msg);
  for (int i = 0; i < 2; ++i, cmsg_hdr = CMSG_NXTHDR(&msg, cmsg_hdr)) {
    cmsg_hdr->cmsg_level = SOL_SOCKET;
    cmsg_hdr->cmsg_type = SCM_RIGHTS;
    cmsg_hdr->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int* fd_out = reinterpret_cast<int*>(CMSG_DATA(cmsg_hdr));
    fd_out[0] = fds[2 * i].get();
    fd_out[1] = fds[2 * i + 1].get();
  }
  msg.msg_controllen = 2 * CMSG_SPACE(2 * sizeof(int));

  ssize_t rc = sendmsg(sockfd, &msg, 0);
  if (rc == -1) {
    err(1, "failed to send fd");
  }
}

static unique_fd PrepareRecvmsg() {
  unique_fd left, right;
  if (!android::base::Socketpair(AF_UNIX, SOCK_SEQPACKET, 0, &left, &right)) {
    err(1, "failed to create socketpair");
  }

  // Send two messages, both containing two SCM_RIGHTS messages with two file descriptors per cmsg.
  SendFds(left.get());
  SendFds(left.get());
  return right;
}

static void VerifyRecvmsg(struct msghdr* msg, const char* expected_function) {
  std::vector<int> fds;

  // The kernel seems to collapse multiple SCM_RIGHTS messages into one.
  for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    int* cmsg_fds = reinterpret_cast<int*>(CMSG_DATA(cmsg));

    ssize_t header_len = CMSG_DATA(cmsg) - reinterpret_cast<unsigned char*>(cmsg);
    ASSERT_GT(header_len, 0);
    ssize_t fd_array_len = cmsg->cmsg_len - header_len;
    ASSERT_GT(fd_array_len, 0);
    size_t fd_count = fd_array_len / sizeof(int);

    for (size_t i = 0; i < fd_count; ++i) {
      fds.push_back(cmsg_fds[i]);
    }
  }

  ASSERT_EQ(4ULL, fds.size());
  int last = -1;
  for (int fd : fds) {
    ASSERT_NE(-1, fd);
    ASSERT_NE(last, fd);
    EXPECT_EQ(expected_function, FdsanWrapperTest::GetFdCreator(fd, false));

    close(fd);
    last = fd;
  }
}

class recvmsg_buf {
 public:
  recvmsg_buf() {
    memset(&iov_, 0, sizeof(iov_));

    iov_.iov_base = msg_buf_;
    iov_.iov_len = sizeof(msg_buf_);
  }

  recvmsg_buf(const recvmsg_buf& copy) = delete;
  recvmsg_buf(recvmsg_buf&& move) = delete;

  recvmsg_buf& operator=(const recvmsg_buf& copy) = delete;
  recvmsg_buf& operator=(recvmsg_buf&& move) = delete;

  void populate(struct msghdr* msg) {
    memset(msg, 0, sizeof(*msg));
    msg->msg_iov = &iov_;
    msg->msg_iovlen = 1;
    msg->msg_control = cmsg_buf_;
    msg->msg_controllen = sizeof(cmsg_buf_);
  }

 private:
  char msg_buf_[128];
  char cmsg_buf_[4096];
  struct iovec iov_;
};

TEST_F(FdsanWrapperTest, recvmsg) {
  unique_fd sockfd = PrepareRecvmsg();

  ClearAllHistory();

  for (int i = 0; i < 2; ++i) {
    recvmsg_buf buf;
    struct msghdr msg;
    buf.populate(&msg);
    ssize_t rc = recvmsg(sockfd.get(), &msg, 0);
    ASSERT_EQ(1LL, rc);
    VerifyRecvmsg(&msg, "recvmsg");
  }
}

TEST_F(FdsanWrapperTest, recvmmsg) {
  unique_fd sockfd = PrepareRecvmsg();

  ClearAllHistory();

  recvmsg_buf buf[2];
  struct mmsghdr msgvec[2];
  buf[0].populate(&msgvec[0].msg_hdr);
  buf[1].populate(&msgvec[1].msg_hdr);

  int rc = recvmmsg(sockfd.get(), msgvec, 2, 0, nullptr);
  ASSERT_EQ(2, rc) << "recvmmsg failed: " << strerror(errno);
  for (int i = 0; i < 2; ++i) {
    VerifyRecvmsg(&msgvec[i].msg_hdr, "recvmmsg");
  }
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

TEST_F(FdsanWrapperTest, android_dlopen_ext) {
  void* result = android_dlopen_ext("/dev/null", 0, nullptr);
  ASSERT_TRUE(result == nullptr);
}
