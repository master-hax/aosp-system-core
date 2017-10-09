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

#include <unistd.h>
#include <sys/socket.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

extern "C" {

int pipe(int pipefd[2]) {
  return fdsan_record_create(__real_pipe(pipefd), "pipe");
}

int pipe2(int pipefd[2], int flags) {
  return fdsan_record_create(__real_pipe2(pipefd, flags), "pipe2");
}

int socket(int domain, int type, int protocol) {
  return fdsan_record_create(__real_socket(domain, type, protocol), "socket");
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
  int rc = __real_socketpair(domain, type, protocol, sv);
  if (rc == 0) {
    fdsan_record_create(sv[0], "socketpair");
    fdsan_record_create(sv[1], "socketpair");
  }
  return rc;
}

int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
  int rc = FDSAN_CHECK(accept, sockfd, addr, addrlen);
  return fdsan_record_create(rc, "accept");
}

int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
  int rc = FDSAN_CHECK(accept4, sockfd, addr, addrlen, flags);
  return fdsan_record_create(rc, "accept4");
}

}  // extern "C"
