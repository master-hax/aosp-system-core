/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <android-base/fork.h>
#include <android-base/local_socket.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <array>
#include <functional>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

using android::base::fork_helper;
using android::base::unique_fd;
using namespace std::placeholders;

void socket_test(unique_fd &send_fd, unique_fd &recv_fd,
                 std::function<ssize_t(int, const void *, size_t)> send_fn,
                 std::function<ssize_t(int, void *, size_t)> recv_fn) {
  const std::array<unsigned char, 4> send_buf{{0x1, 0x2, 0x3, 0x4}};
  auto send_err =
      TEMP_FAILURE_RETRY(send_fn(send_fd, send_buf.begin(), send_buf.size()));
  ASSERT_GE(send_err, 0) << "sending buffer failed: " << strerror(errno);
  ASSERT_EQ(static_cast<ssize_t>(send_buf.size()), send_err);

  std::array<unsigned char, 4> recv_buf;
  auto recv_err =
      TEMP_FAILURE_RETRY(recv_fn(recv_fd, recv_buf.begin(), recv_buf.size()));
  ASSERT_GE(recv_err, 0) << "receiving buffer failed: " << strerror(errno);
  ASSERT_EQ(static_cast<ssize_t>(recv_buf.size()), recv_err);

  ASSERT_EQ(send_buf, recv_buf);
}

TEST(local_socket, pipe) {
  unique_fd recv_fd, send_fd;
  ASSERT_TRUE(pipe(recv_fd, send_fd));

  ASSERT_NO_FATAL_FAILURE(socket_test(send_fd, recv_fd, write, read));
}

TEST(local_socket, socketpair) {
  unique_fd recv_fd, send_fd;
  ASSERT_TRUE(socketpair(recv_fd, send_fd));

  auto send_fn = std::bind(send, _1, _2, _3, MSG_DONTWAIT);
  auto recv_fn = std::bind(recv, _1, _2, _3, MSG_WAITALL);
  ASSERT_NO_FATAL_FAILURE(socket_test(send_fd, recv_fd, send_fn, recv_fn));
}

constexpr int PINGPONG_ITERS = 10000;

void pingpong_parent(unique_fd &sock) {
  for (int i = 0; i < PINGPONG_ITERS; i++) {
    unique_fd out_fd{open("/dev/null", O_RDONLY)};
    ASSERT_NE(-1, out_fd) << "opening /dev/null failed: " << strerror(errno);
    ASSERT_TRUE(sendfd(sock, out_fd)) << "sendfd() failed: " << strerror(errno);

    unique_fd in_fd;
    ASSERT_TRUE(recvfd(sock, in_fd)) << "recvfd() failed: " << strerror(errno);

    ASSERT_NE(out_fd, in_fd) << "fd wasn't duplicated during round trip";
    ASSERT_GE(in_fd, 0) << "received invalid fd";

#if defined(__linux__)  // This test requires procfs
    std::stringstream ss;
    ss << "/proc/self/fd/" << in_fd.get();
    auto fdPath = ss.str();

    char path[PATH_MAX]{};
    auto err = readlink(fdPath.c_str(), path, sizeof(path));
    ASSERT_NE(-1, err) << "readlink() failed: " << strerror(errno);
    ASSERT_STREQ("/dev/null", path) << "fd target didn't survive round trip";
#endif
  }
}

template <typename FD_TYPE>
int pingpong_child(unique_fd &sock) {
  for (int i = 0; i < PINGPONG_ITERS; i++) {
    FD_TYPE fd;
    if (!recvfd(sock, fd)) return 1;
    if (!sendfd(sock, fd)) return 1;
  }

  return 0;
}

TEST(local_socket, pingpong_int) {
  unique_fd parent_sock, child_sock;
  ASSERT_TRUE(socketpair(parent_sock, child_sock));

  fork_helper<unique_fd &> f{[](unique_fd &sock) {
    return pingpong_child<int>(sock);
  }, child_sock};

  ASSERT_NO_FATAL_FAILURE(pingpong_parent(parent_sock));
  ASSERT_TRUE(f.wait());
}

TEST(local_socket, pingpong_uniquefd) {
  unique_fd parent_sock, child_sock;
  ASSERT_TRUE(socketpair(parent_sock, child_sock));

  fork_helper<unique_fd &> f{[](unique_fd &sock) {
    return pingpong_child<unique_fd>(sock);
  }, child_sock};

  ASSERT_NO_FATAL_FAILURE(pingpong_parent(parent_sock));
  ASSERT_TRUE(f.wait());
}
