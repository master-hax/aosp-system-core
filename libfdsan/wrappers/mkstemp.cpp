/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "fdsan.h"
#include "fdsan_wrappers.h"

extern "C" {

int mkstemp(char* path) {
  return fdsan_record_create(__real_mkstemp(path), "mkstemp");
}

int mkstemp64(char* path) {
  return fdsan_record_create(__real_mkstemp64(path), "mkstemp64");
}

int mkostemp(char* path, int flags) {
  return fdsan_record_create(__real_mkostemp(path, flags), "mkostemp");
}

int mkostemp64(char* path, int flags) {
  return fdsan_record_create(__real_mkostemp64(path, flags), "mkostemp64");
}

int mkstemps(char* path, int flags) {
  return fdsan_record_create(__real_mkstemps(path, flags), "mkstemps");
}

int mkstemps64(char* path, int flags) {
  return fdsan_record_create(__real_mkstemps64(path, flags), "mkstemps64");
}

int mkostemps(char* path, int suffix_length, int flags) {
  return fdsan_record_create(__real_mkostemps(path, suffix_length, flags), "mkostemps");
}

int mkostemps64(char* path, int suffix_length, int flags) {
  return fdsan_record_create(__real_mkostemps64(path, suffix_length, flags), "mkostemps64");
}

}  // extern "C"
