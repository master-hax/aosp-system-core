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

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "android-base/multiprocess.h"

namespace android {
namespace base {

unique_socketpair::unique_socketpair() : sp{}, ok{false} {
  int fds[2];

  auto err = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  if (!err) {
    sp[0].reset(fds[0]);
    sp[1].reset(fds[1]);
    ok = true;
  }
}

local_socketstream::local_socketstream(int fd) : sock{fd}, ok{fd != -1} {}

local_socketstream::local_socketstream(unique_socketpair &sp,
                                       const fork_helper &f)
    : local_socketstream{} {
  if (sp && f) {
    sock.reset(sp.release(f.is_parent()));
    ok = true;
  }
}

local_socketstream &local_socketstream::operator<<(const unique_fd &val) {
  char unused = 0;
  send_cmsg(&unused, sizeof(unused), val.get());
  return *this;
}

local_socketstream &local_socketstream::operator>>(unique_fd &val) {
  int fd;
  char unused;

  recv_cmsg(&unused, sizeof(unused), &fd);
  if (ok)
    val.reset(fd);
  else
    val.clear();
  return *this;
}

void local_socketstream::send_cmsg(const void *buf, std::size_t size, int fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(fd))];

  iovec iov{};
  iov.iov_base = const_cast<void *>(buf);
  iov.iov_len = size;

  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if (fd != -1) {
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    auto cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

    auto fdBuf = reinterpret_cast<int *>(CMSG_DATA(cmsg));
    *fdBuf = fd;
  }

  ok = TEMP_FAILURE_RETRY(sendmsg(sock.get(), &msg, 0)) >= 0;
}

void local_socketstream::recv_cmsg(void *buf, std::size_t size, int *fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(*fd))];

  iovec iov{};
  iov.iov_base = buf;
  iov.iov_len = size;

  msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if (fd) {
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    auto cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*fd));
  }

  ok = TEMP_FAILURE_RETRY(recvmsg(sock.get(), &msg, 0)) >= 0;
  if (ok && fd) {
    auto cmsg = CMSG_FIRSTHDR(&msg);
    auto fdBuf = reinterpret_cast<int *>(CMSG_DATA(cmsg));
    *fd = *fdBuf;
  }
}

bool fork_helper::kill_child(int sig) {
  if (!is_parent()) return false;

  auto err = kill(pid, sig);
  if (err < 0) return false;

  int s;
  auto p = waitpid(pid, &s, 0);
  return p == pid && WIFSIGNALED(s) && WTERMSIG(s) == sig;
}

bool fork_helper::wait_for_child(int status) {
  if (!is_parent()) return false;

  int s;
  auto p = waitpid(pid, &s, 0);
  return p == pid && WIFEXITED(s) && WEXITSTATUS(s) == status;
}

};  // namespace base
};  // namespace android
