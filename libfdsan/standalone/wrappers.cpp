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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "fdsan_wrappers.h"

extern "C" {

int __real_close(int fd) {
  return close(fd);
}

// Sketchy, but happens to work for all of our ABIs.
int __real_openat(int fd, const char* pathname, int flags, int mode) {
  return openat(fd, pathname, flags, mode);
}

int __real_dup(int fd) {
  return dup(fd);
}

int __real_dup2(int oldfd, int newfd) {
  return dup2(oldfd, newfd);
}

int __real_dup3(int oldfd, int newfd, int flags) {
  return dup3(oldfd, newfd, flags);
}

int __real_fcntl(int fd, int cmd, void* arg) {
  return fcntl(fd, cmd, arg);
}

int __real_mkstemp(char* path) {
  return mkstemp(path);
}

int __real_mkstemp64(char* path) {
  return mkstemp64(path);
}

int __real_mkostemp(char* path, int flags) {
  return mkostemp(path, flags);
}

int __real_mkostemp64(char* path, int flags) {
  return mkostemp64(path, flags);
}

int __real_mkstemps(char* path, int flags) {
  return mkstemps(path, flags);
}

int __real_mkstemps64(char* path, int flags) {
  return mkstemps64(path, flags);
}

int __real_mkostemps(char* path, int suffix_length, int flags) {
  return mkostemps(path, suffix_length, flags);
}

int __real_mkostemps64(char* path, int suffix_length, int flags) {
  return mkostemps64(path, suffix_length, flags);
}

int __real_pipe(int pipefd[2]) {
  return pipe(pipefd);
}

int __real_pipe2(int pipefd[2], int flags) {
  return pipe2(pipefd, flags);
}

int __real_socket(int domain, int type, int protocol) {
  return socket(domain, type, protocol);
}

int __real_socketpair(int domain, int type, int protocol, int sv[2]) {
  return socketpair(domain, type, protocol, sv);
}

int __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
  return accept(sockfd, addr, addrlen);
}

int __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
  return accept4(sockfd, addr, addrlen, flags);
}

int __real_epoll_create(int size) {
  return epoll_create(size);
}

int __real_epoll_create1(int flags) {
  return epoll_create1(flags);
}

int __real_eventfd(unsigned int initval, int flags) {
  return eventfd(initval, flags);
}

int __real_inotify_init() {
  return inotify_init();
}

int __real_inotify_init1(int flags) {
  return inotify_init1(flags);
}

int __real_signalfd(int fd, const sigset_t* mask, int flags) {
  return signalfd(fd, mask, flags);
}

int __real_timerfd_create(int clockid, int flags) {
  return timerfd_create(clockid, flags);
}

}  // extern "C"
