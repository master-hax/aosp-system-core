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

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

extern "C" {

int epoll_create(int size) {
  return fdsan_record_create(__real_epoll_create(size), "epoll_create");
}

int epoll_create1(int flags) {
  return fdsan_record_create(__real_epoll_create1(flags), "epoll_create1");
}

int eventfd(unsigned int initval, int flags) {
  return fdsan_record_create(__real_eventfd(initval, flags), "eventfd");
}

int inotify_init() {
  return fdsan_record_create(__real_inotify_init(), "inotify_init");
}

int inotify_init1(int flags) {
  return fdsan_record_create(__real_inotify_init1(flags), "inotify_init1");
}

int signalfd(int fd, const sigset_t* mask, int flags) {
  int rc = FDSAN_CHECK(signalfd, fd, mask, flags);
  // TODO: If EINVAL, print what we think fd is if flags seem valid?
  return fdsan_record_create(rc, "signalfd");
}

int timerfd_create(int clockid, int flags) {
  return fdsan_record_create(__real_timerfd_create(clockid, flags), "timerfd_create");
}

}  // extern "C"
