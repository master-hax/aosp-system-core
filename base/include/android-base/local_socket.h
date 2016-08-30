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

#ifndef ANDROID_BASE_LOCAL_SOCKET_H
#define ANDROID_BASE_LOCAL_SOCKET_H

#include <android-base/unique_fd.h>
#include <sys/socket.h>

namespace android {
namespace base {

// Wraps pipe()/pipe2(), storing the created pipe in two unique_fds.
// Returns whether the pipe was successfully created (and sets errno on
// failure).
bool pipe(unique_fd &pipefd_read, unique_fd &pipefd_write, int flags = 0);

// Wraps socketpair(), storing the created socketpair in two unique_fds.
// Returns whether the socketpair was successfully created (and sets errno on
// failure).
bool socketpair(unique_fd &sv1, unique_fd &sv2, int domain = AF_UNIX,
                int type = SOCK_STREAM, int protocol = 0);

// Uses cmsg(3) to send an fd over a local socket.  Returns whether the
// send succeeded (and sets errno on failure).
bool sendfd(int sockfd, int sharefd, int flags = 0);

// Uses cmsg(3) to receive an fd from a local socket.  Returns whether the
// receive succeeded (and sets errno on failure).
bool recvfd(int sockfd, int &sharefd, int flags = 0);
bool recvfd(int sockfd, unique_fd &sharefd, int flags = 0);

};  // namespace base
};  // namespace android

#endif  // ANDROID_BASE_LOCAL_SOCKET_H
