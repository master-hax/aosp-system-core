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

#include <utils/FileMap.h>
#include <ziparchive/zip_archive.h>

class desp {
 public:
  bool file_type;
  const int fd;
  uint8_t* read_pos;
  const android::FileMap* file_map;

  desp(const int fd) : file_type(true), fd(fd), read_pos(nullptr), file_map(nullptr) {}

  desp(const android::FileMap* file_map) :
    file_type(false),
    fd(-1),
    read_pos(static_cast<uint8_t*>(file_map->getDataPtr())),
    file_map(file_map){}

  off64_t getFileLength();

  bool seekToOffset(off64_t offset);

  bool readData(uint8_t* buffer, size_t read_amount);
};

struct ZipArchive {
  // open Zip archive
  //const int fd;
  desp des_fd;
  const bool close_file;

  // mapped central directory area
  off64_t directory_offset;
  android::FileMap directory_map;

  // number of entries in the Zip archive
  uint16_t num_entries;

  // We know how many entries are in the Zip archive, so we can have a
  // fixed-size hash table. We define a load factor of 0.75 and over
  // allocate so the maximum number entries can never be higher than
  // ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
  uint32_t hash_table_size;
  ZipString* hash_table;

  ZipArchive(const int fd, bool assume_ownership) :
      des_fd(fd),
      close_file(assume_ownership),
      directory_offset(0),
      num_entries(0),
      hash_table_size(0),
      hash_table(NULL) {}

  ZipArchive(const android::FileMap* file_map) :
      des_fd(file_map),
      close_file(false),
      directory_offset(0),
      num_entries(0),
      hash_table_size(0),
      hash_table(NULL) {}

  ~ZipArchive() {
    if (close_file && des_fd.fd >= 0) {
      close(des_fd.fd);
    }

    free(hash_table);
  }
};

#endif  // LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_
