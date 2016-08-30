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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstddef>
#include <cstdlib>
#include <type_traits>

#include <android-base/unique_fd.h>

namespace android {
namespace base {

// Wraps pipe()/pipe2(), storing the created pipe in a unique_fd[2].
// Returns whether the pipe was successfully created (and sets errno on
// failure).
bool pipe(unique_fd pipefd[2], int flags = 0);

// Wraps socketpair(), storing the created socketpair in a unique_fd[2].
// Returns whether the socketpair was successfully created (and sets errno on
// failure).
bool socketpair(unique_fd sv[2], int domain = AF_UNIX, int type = SOCK_STREAM,
                int protocol = 0);

// Uses cmsg(3) to send an fd over a local socket, along with an optional
// payload.  Returns whether the entire message was succesfully sent.
bool send_cmsg(int sockfd, int sharefd, const void *buf = nullptr,
               std::size_t len = 0, int flags = 0);

// Uses cmsg(3) to receive an fd from a local socket, along with an optional
// payload.  Returns whether the entire message was succesfully received.
bool recv_cmsg(int sockfd, int &sharefd, void *buf = nullptr,
               std::size_t len = 0, int flags = 0);
bool recv_cmsg(int sockfd, unique_fd &sharefd, void *buf = nullptr,
               std::size_t len = 0, int flags = 0);

};  // namespace base
};  // namespace android

#endif  // ANDROID_BASE_LOCAL_SOCKET_H
