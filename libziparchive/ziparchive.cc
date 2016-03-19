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

#include <ziparchive/ziparchive.h>

#include <fcntl.h>

#include <android-base/logging.h>

static void SetCloseOnExec(int fd) {
  // This dance is more portable than Linux's O_CLOEXEC open(2) flag.
  int flags = fcntl(fd, F_GETFD);
  if (flags == -1) {
    PLOG(WARNING) << "fcntl(" << fd << ", F_GETFD) failed";
    return;
  }
  int rc = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  if (rc == -1) {
    PLOG(WARNING) << "fcntl(" << fd << ", F_SETFD, " << flags << ") failed";
    return;
  }
}

ZipArchive* ZipArchive::Open(const char* filename, std::string* error_msg) {
  DCHECK(filename != nullptr);

  ZipArchiveHandle handle;
  const int32_t error = OpenArchive(filename, &handle);
  if (error) {
    *error_msg = std::string(ErrorCodeString(error));
    CloseArchive(handle);
    return nullptr;
  }

  SetCloseOnExec(GetFileDescriptor(handle));
  return new ZipArchive(handle);
}

ZipArchive* ZipArchive::OpenFromFd(int fd, const char* filename, std::string* error_msg) {
  DCHECK(filename != nullptr);
  DCHECK_GT(fd, 0);

  ZipArchiveHandle handle;
  const int32_t error = OpenArchiveFd(fd, filename, &handle);
  if (error) {
    *error_msg = std::string(ErrorCodeString(error));
    CloseArchive(handle);
    return nullptr;
  }

  SetCloseOnExec(GetFileDescriptor(handle));
  return new ZipArchive(handle);
}

ZipArchive::~ZipArchive() {
  CloseArchive(handle_);
}
