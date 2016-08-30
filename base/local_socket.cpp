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

#include <android-base/local_socket.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace android {
namespace base {

static inline bool fd_pair_to_unique_fd(int fds[2], unique_fd sv[2], int err) {
  if (err < 0) return false;

  sv[0].reset(fds[0]);
  sv[1].reset(fds[1]);
  return true;
}

bool pipe(unique_fd pipefd[2], int flags) {
  int fds[2];
  auto err = ::pipe2(fds, flags);
  return fd_pair_to_unique_fd(fds, pipefd, err);
}

bool socketpair(unique_fd sv[2], int domain, int type, int protocol) {
  int fds[2];
  auto err = ::socketpair(domain, type, protocol, fds);
  return fd_pair_to_unique_fd(fds, sv, err);
}

bool send_cmsg(int sockfd, int sharefd, const void *buf, std::size_t len,
               int flags) {
  const char unused = 1;
  if (!buf && !len) {
    buf = &unused;
    len = sizeof(unused);
  } else if (!buf || !len) {
    errno = EINVAL;
    return false;
  }

  iovec iov{};
  iov.iov_base = const_cast<void *>(buf);
  iov.iov_len = len;

  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  char cmsg_buf[CMSG_SPACE(sizeof(sharefd))];
  msg.msg_control = cmsg_buf;
  msg.msg_controllen = sizeof(cmsg_buf);

  auto cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(sharefd));

  auto sharefd_buf = reinterpret_cast<int *>(CMSG_DATA(cmsg));
  *sharefd_buf = sharefd;

  auto s = TEMP_FAILURE_RETRY(sendmsg(sockfd, &msg, flags));
  return s == static_cast<ssize_t>(len);
}

bool recv_cmsg(int sockfd, int &sharefd, void *buf, std::size_t len,
               int flags) {
  char unused;
  if (!buf && !len) {
    buf = &unused;
    len = sizeof(unused);
  } else if (!buf || !len) {
    errno = EINVAL;
    return false;
  }

  iovec iov{};
  iov.iov_base = buf;
  iov.iov_len = len;

  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  char cmsg_buf[CMSG_SPACE(sizeof(sharefd))];
  msg.msg_control = cmsg_buf;
  msg.msg_controllen = sizeof(cmsg_buf);

  auto cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(sharefd));

  auto s = TEMP_FAILURE_RETRY(recvmsg(sockfd, &msg, flags));
  if (s != static_cast<ssize_t>(len)) return false;

  auto sharefd_buf = reinterpret_cast<int *>(CMSG_DATA(cmsg));
  sharefd = *sharefd_buf;
  return true;
}

bool recv_cmsg(int sockfd, unique_fd &sharefd, void *buf, std::size_t len,
               int flags) {
  int sharefd_int;
  bool ret = recv_cmsg(sockfd, sharefd_int, buf, len, flags);
  if (ret) sharefd.reset(sharefd_int);
  return ret;
}

};  // namespace base
};  // namespace android
