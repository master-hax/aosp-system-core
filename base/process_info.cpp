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

#include "android-base/process_info.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include "android-base/unique_fd.h"

namespace android {
namespace base {

bool GetProcessInfo(ProcessInfo* process_info, pid_t tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d", tid);

  unique_fd dirfd(open(path, O_DIRECTORY | O_RDONLY));
  if (dirfd == -1) {
    PLOG(ERROR) << "failed to open " << path;
    return false;
  }

  return GetProcessInfoFromProcPidFd(process_info, dirfd.get());
}

bool GetProcessInfoFromProcPidFd(ProcessInfo* process_info, int fd) {
  int status_fd = openat(fd, "status", O_RDONLY);

  if (status_fd == -1) {
    PLOG(ERROR) << "failed to open status fd in GetProcessInfoFromProcPidFd";
    return false;
  }

  FILE* fp = fdopen(status_fd, "r");
  if (!fp) {
    PLOG(ERROR) << "failed to open status file in GetProcessInfoFromProcPidFd";
    close(status_fd);
    return false;
  }

  int fields = 0;
  char line[1024];

  while (fgets(line, sizeof(line), fp)) {
    char* tab = strchr(line, '\t');
    if (tab == nullptr) {
      continue;
    }

    size_t len = tab - line;
    std::string header = std::string(line, len);
    if (header == "Pid:") {
      process_info->tid = atoi(tab + 1);
      fields |= 1;
    } else if (header == "Tgid:") {
      process_info->pid = atoi(tab + 1);
      fields |= 2;
    } else if (header == "PPid:") {
      process_info->ppid = atoi(tab + 1);
      fields |= 4;
    } else if (header == "TracerPid:") {
      process_info->tracer = atoi(tab + 1);
      fields |= 8;
    } else if (header == "Uid:") {
      process_info->uid = atoi(tab + 1);
      fields |= 16;
    } else if (header == "Gid:") {
      process_info->gid = atoi(tab + 1);
      fields |= 32;
    }
  }

  fclose(fp);
  return fields == 63;
}

} /* namespace base */
} /* namespace android */
