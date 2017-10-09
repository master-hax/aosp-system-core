#pragma once

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

#include <sys/signalfd.h>
#include <sys/socket.h>

extern "C" {

int __real_close(int fd);

int __real_openat(int fd, const char* pathname, int flags, int mode);

int __real_dup(int fd);
int __real_dup2(int oldfd, int newfd);
int __real_dup3(int oldfd, int newfd, int flags);
int __real_fcntl(int fd, int cmd, void* arg);

int __real_mkstemp(char* path);
int __real_mkstemp64(char* path);
int __real_mkostemp(char* path, int flags);
int __real_mkostemp64(char* path, int flags);
int __real_mkstemps(char* path, int flags);
int __real_mkstemps64(char* path, int flags);
int __real_mkostemps(char* path, int suffix_length, int flags);
int __real_mkostemps64(char* path, int suffix_length, int flags);

int __real_socket(int domain, int type, int protocol);
int __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);

int __real_epoll_create(int size);
int __real_epoll_create1(int flags);
int __real_eventfd(unsigned int initval, int flags);
int __real_inotify_init();
int __real_inotify_init1(int flags);
int __real_signalfd(int fd, const sigset_t* mask, int flags);
int __real_timerfd_create(int clockid, int flags);

}  // extern "C"
