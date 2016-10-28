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

#define LOG_TAG "DEBUG"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android/log.h>

#include "open_files_list.h"

#include "utility.h"

void populate_open_files_list(pid_t pid, OpenFilesList* list) {
  char fd_dir_name[16];
  snprintf(fd_dir_name, sizeof(fd_dir_name), "/proc/%d/fd", pid);
  DIR* dir = opendir(fd_dir_name);
  if (dir == NULL) {
    ALOGE("failed to open directory /proc/%d/fd", pid);
    return;
  }

  struct dirent* de;
  for (de = readdir(dir); de != nullptr; de = readdir(dir)) {
    if (*de->d_name == '.') {
      continue;
    }

    char path[32];
    char buf[1024];
    int fd = atoi(de->d_name);
    snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, de->d_name);
    ssize_t size = readlink(path, buf, sizeof(buf));
    if (size < 0) {
      ALOGE("failed to readlink %s", path);
      list->emplace_back(fd, "???");
      continue;
    }
    list->emplace_back(fd, std::string(buf, size));
  }
}

void dump_open_files_list_to_log(const OpenFilesList& files, log_t* log, const char* prefix) {
  for (std::pair<int, std::string> file : files) {
    _LOG(log, logtype::OPEN_FILES, "%sfd %i: %s\n", prefix, file.first, file.second.c_str());
  }
}

