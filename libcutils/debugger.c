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

#include <cutils/debugger.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/log.h>

int dump_backtrace_to_file(pid_t tid, int fd) {
  char buf[3 * sizeof(int) + 1];
  snprintf(buf, sizeof(buf), "%d", (int)tid);

  pid_t forkpid = fork();
  if (forkpid == 0) {
    dup2(fd, STDOUT_FILENO);
    execl("/system/bin/debuggerd", "/system/bin/debuggerd", "-b", buf, NULL);
    ALOGE("debuggerd exec failed: %s", strerror(errno));
    _exit(1);
  }

  int status;
  pid_t rc = waitpid(forkpid, &status, 0);
  if (rc != forkpid) {
    ALOGE("waitpid failed while dumping backtrace for pid %d: %s", tid, strerror(errno));
    return -1;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    ALOGE("debuggerd reported failure when dumping pid %s", buf);
    return -1;
  }

  return 0;
}

int dump_backtrace_to_file_timeout(pid_t tid, int fd, int timeout_secs) {
  // TODO: Actually timeout.
  (void)timeout_secs;
  return dump_backtrace_to_file(tid, fd);
}
