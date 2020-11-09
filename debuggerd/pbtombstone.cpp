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

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <libdebuggerd/tombstone.h>

#include "tombstone.pb.h"

using android::base::unique_fd;

int main(int argc, const char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: pbtombstone TOMBSTONE.PB\n");
    exit(1);
  }

  unique_fd fd(open(argv[1], O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    err(1, "failed to open tombstone '%s'", argv[1]);
  }

  Tombstone tombstone;
  if (!tombstone.ParseFromFileDescriptor(fd.get())) {
    err(1, "failed to parse tombstone");
  }

  bool result = proto_tombstone_to_text(
      tombstone, [](const std::string& line, bool) { printf("%s\n", line.c_str()); });

  if (!result) {
    errx(1, "tombstone was malformed");
  }
}
