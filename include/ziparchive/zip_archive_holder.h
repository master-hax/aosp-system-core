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
#ifndef LIBZIPARCHIVE_ZIP_ARCHIVE_HOLDER_H_
#define LIBZIPARCHIVE_ZIP_ARCHIVE_HOLDER_H_

#include <memory>
#include <string>

#include <android-base/macros.h>
#include <ziparchive/zip_archive.h>

class ZipArchiveHolder {
 public:
  // return new ZipArchive instance on success, null on error.
  static std::unique_ptr<ZipArchiveHolder> Open(const char* filename, std::string* error_msg);
  static std::unique_ptr<ZipArchiveHolder> OpenFromFd(int fd, const char* filename,
                                                      std::string* error_msg);

  ~ZipArchiveHolder();

  ZipArchiveHandle handle() const {
    return handle_;
  }
  int fd() const {
    return GetFileDescriptor(handle_);
  }

 private:
  explicit ZipArchiveHolder(ZipArchiveHandle handle) : handle_(handle) {}

  ZipArchiveHandle handle_;

  DISALLOW_COPY_AND_ASSIGN(ZipArchiveHolder);
};

#endif  // LIBZIPARCHIVE_ZIP_ARCHIVE_HOLDER_H_
