/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "debuggerd/util.h"

#include <sys/socket.h>

#include <utility>

#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/protocol.h"

using android::base::unique_fd;

ssize_t send_fd(int sockfd, const void* data, size_t len, unique_fd fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(int))];

  iovec iov = { .iov_base = const_cast<void*>(data), .iov_len = len };
  msghdr msg = {
    .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cmsg_buf, .msg_controllen = sizeof(cmsg_buf),
  };
  auto cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = fd.get();

  return TEMP_FAILURE_RETRY(sendmsg(sockfd, &msg, 0));
}

ssize_t recv_fd(int sockfd, void* _Nonnull data, size_t len,
                unique_fd* _Nullable out_fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(int))];

  iovec iov = { .iov_base = const_cast<void*>(data), .iov_len = len };
  msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf),
    .msg_flags = 0,
  };
  auto cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));

  ssize_t result = TEMP_FAILURE_RETRY(recvmsg(sockfd, &msg, 0));
  if (result == -1) {
    return -1;
  }

  unique_fd fd;
  bool received_fd = msg.msg_controllen == sizeof(cmsg_buf);
  if (received_fd) {
    fd.reset(*reinterpret_cast<int*>(CMSG_DATA(cmsg)));
  }

  if ((msg.msg_flags & MSG_TRUNC) != 0) {
    errno = EFBIG;
    return -1;
  } else if ((msg.msg_flags & MSG_CTRUNC) != 0) {
    errno = ERANGE;
    return -1;
  }

  if (out_fd) {
    *out_fd = std::move(fd);
  } else if (received_fd) {
    errno = ERANGE;
    return -1;
  }

  return result;
}

bool Pipe(unique_fd* read, unique_fd* write) {
  int pipefds[2];
  if (pipe(pipefds) != 0) {
    return false;
  }
  read->reset(pipefds[0]);
  write->reset(pipefds[1]);
  return true;
}

bool tombstoned_connect(pid_t pid, unique_fd* tombstoned_socket, unique_fd* output_fd) {
  unique_fd sockfd(socket_local_client(kTombstonedCrashSocketName,
                                       ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (sockfd == -1) {
    __libc_format_log(ANDROID_LOG_ERROR, "libc", "failed to connect to tombstoned: %s",
                      strerror(errno));
    return false;
  }

  TombstonedCrashPacket packet = {};
  packet.packet_type = CrashPacketType::kDumpRequest;
  packet.packet.dump_request.pid = pid;
  if (TEMP_FAILURE_RETRY(write(sockfd, &packet, sizeof(packet))) != sizeof(packet)) {
    __libc_format_log(ANDROID_LOG_ERROR, "libc", "failed to write DumpRequest packet: %s",
                      strerror(errno));
    return false;
  }

  unique_fd tmp_output_fd;
  ssize_t rc = recv_fd(sockfd, &packet, sizeof(packet), &tmp_output_fd);
  if (rc == -1) {
    __libc_format_log(ANDROID_LOG_ERROR, "libc", "failed to read response to DumpRequest packet: %s",
                      strerror(errno));
    return false;
  } else if (rc != sizeof(packet)) {
    __libc_format_log(
      ANDROID_LOG_ERROR, "libc",
      "received DumpRequest response packet of incorrect length (expected %zu, got %zd)",
      sizeof(packet), rc);
    return false;
  }

  // Make the fd O_APPEND so that our output is guaranteed to be at the end of a file.
  // (This also makes selinux rules consistent, because selinux distinguishes between writing to
  // a regular fd, and writing to an fd with O_APPEND).
  int flags = fcntl(tmp_output_fd.get(), F_GETFL);
  if (fcntl(tmp_output_fd.get(), F_SETFL, flags | O_APPEND) != 0) {
    __libc_format_log(ANDROID_LOG_WARN, "libc", "failed to set output fd flags: %s",
                      strerror(errno));
  }

  *tombstoned_socket = std::move(sockfd);
  *output_fd = std::move(tmp_output_fd);
  return true;
}

bool tombstoned_notify_completion(int tombstoned_socket) {
  TombstonedCrashPacket packet = {};
  packet.packet_type = CrashPacketType::kCompletedDump;
  if (TEMP_FAILURE_RETRY(write(tombstoned_socket, &packet, sizeof(packet))) != sizeof(packet)) {
    return false;
  }
  return true;
}
