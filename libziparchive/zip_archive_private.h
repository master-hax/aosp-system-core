/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_
#define LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <utils/FileMap.h>
#include <ziparchive/zip_archive.h>

class MappedZipFile {
 private:
  bool has_fd;
  const int fd;
  size_t read_pos;
  void* base_ptr;
  off64_t data_length;

 public:
  MappedZipFile(const int fd) :
    has_fd(true),
    fd(fd),
    read_pos(0),
    base_ptr(nullptr),
    data_length(0){}

  MappedZipFile(void* address, size_t length) :
    has_fd(false),
    fd(-1),
    read_pos(0),
    base_ptr(address),
    data_length(static_cast<off64_t>(length)){}

  bool HasFd() {return has_fd;}

  int GetFileDescriptor();

  void* GetBasePtr();

  off64_t GetFileLength();

  bool SeekToOffset(off64_t offset);

  bool ReadData(uint8_t* buffer, size_t read_amount);

  bool ReadAtOffset(uint8_t* buf, size_t len, off64_t off);
};

class CentralDirectory {
 public:
  uint8_t* base_ptr;
  size_t length;

  CentralDirectory(void) :
    base_ptr(nullptr),
    length(0) {}

  void Initialize(void* map_base_ptr, off64_t cd_start_offset, size_t cd_size);

};

struct ZipArchive {
  // open Zip archive
  mutable MappedZipFile mapped_zip;
  const bool close_file;

  // mapped central directory area
  off64_t directory_offset;
  CentralDirectory central_directory;
  std::unique_ptr<android::FileMap> directory_map;

  // number of entries in the Zip archive
  uint16_t num_entries;

  // We know how many entries are in the Zip archive, so we can have a
  // fixed-size hash table. We define a load factor of 0.75 and over
  // allocate so the maximum number entries can never be higher than
  // ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
  uint32_t hash_table_size;
  ZipString* hash_table;

  ZipArchive(const int fd, bool assume_ownership) :
    mapped_zip(fd),
    close_file(assume_ownership),
    directory_offset(0),
    central_directory(),
    directory_map(new android::FileMap()),
    num_entries(0),
    hash_table_size(0),
    hash_table(NULL) {}

  ZipArchive(void* address, size_t length) :
    mapped_zip(address, length),
    close_file(false),
    directory_offset(0),
    central_directory(),
    directory_map(new android::FileMap()),
    num_entries(0),
    hash_table_size(0),
    hash_table(NULL) {}

  ~ZipArchive() {
    if (close_file && mapped_zip.GetFileDescriptor() >= 0) {
      close(mapped_zip.GetFileDescriptor());
    }

    free(hash_table);
  }

  bool InitializeCentralDirectory(const char* debug_file_name, off64_t cd_start_offset,
                                  size_t cd_size);

};

#endif  // LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_
