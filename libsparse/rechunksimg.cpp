/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sparse/sparse.h>
#include "backed_block.h"
#include "sparse_file.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

void usage() {
  fprintf(stderr, "Usage: rechunksimg <input sparse image file> <output sparse image file> <max chunk size>\n");
}

int main(int argc, char* argv[]) {
  int in;
  int out;
  int ret;
  struct backed_block* bb;
  struct sparse_file* s;
  int64_t max_size;
  int files;

  if (argc != 4) {
    usage();
    exit(-1);
  }

  max_size = atoll(argv[3]);

  in = open(argv[1], O_RDONLY | O_BINARY);
  if (in < 0) {
    fprintf(stderr, "Cannot open input file %s\n", argv[1]);
    exit(-1);
  }

  out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
  if (out < 0) {
    fprintf(stderr, "Cannot open output file %s\n", argv[2]);
    exit(-1);
  }

  s = sparse_file_import(in, true, false);
  if (!s) {
    fprintf(stderr, "Failed to import sparse file\n");
    exit(-1);
  }

  for (bb = backed_block_iter_new(s->backed_block_list);
       bb; bb = backed_block_iter_next(bb)) {
    ret = backed_block_split(s->backed_block_list, bb, max_size);
    if (ret != 0) {
      fprintf(stderr, "Failed to resparse, error: %d\n", ret);
      exit(-1);
    }
  }

  ret = sparse_file_write(s, out, false, true, false);
  if (ret) {
    fprintf(stderr, "Failed to write sparse file\n");
    exit(-1);
  }

  close(out);
  close(in);

  exit(0);
}
