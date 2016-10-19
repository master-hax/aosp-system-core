/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "DEBUG"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <android/log.h>
#include <cutils/debugger.h>
#include <cutils/sockets.h>

int dump_backtrace_to_file(pid_t tid, int fd) {
  (void)tid, (void)fd;
  // TODO: implement me
  abort();
}

int dump_backtrace_to_file_timeout(pid_t tid, int fd, int timeout_secs) {
  (void)tid, (void)fd, (void)timeout_secs;
  abort();
}
