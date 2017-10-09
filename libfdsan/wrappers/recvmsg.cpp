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

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

static void __attribute__((always_inline))
parse_msghdr(struct msghdr* hdr, const char* function_name) {
  for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(hdr); cmsg != nullptr; cmsg = CMSG_NXTHDR(hdr, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
      continue;
    }

    int* fd_array = reinterpret_cast<int*>(CMSG_DATA(cmsg));
    ssize_t header_len = CMSG_DATA(cmsg) - reinterpret_cast<unsigned char*>(cmsg);
    ssize_t fd_array_len = cmsg->cmsg_len - header_len;
    size_t fd_count = fd_array_len / sizeof(int);
    for (size_t i = 0; i < fd_count; ++i) {
      fdsan_record_create(fd_array[i], function_name);
    }
  }
}

extern "C" {

ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags) {
  ssize_t rc = FDSAN_CHECK(recvmsg, sockfd, msg, flags);
  if (rc != -1) {
    parse_msghdr(msg, "recvmsg");
  }
  return rc;
}

int recvmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags,
             recvmmsg_timespec_t timeout) {
  int rc = FDSAN_CHECK(recvmmsg, sockfd, msgvec, vlen, flags, timeout);
  if (rc != -1) {
    for (int i = 0; i < rc; ++i) {
      parse_msghdr(&msgvec[i].msg_hdr, "recvmmsg");
    }
  }
  return rc;
}

}  // extern "C"
