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

#include <dlfcn.h>

#include "fdsan.h"

extern "C" {

struct android_dlextinfo;
__attribute__((__weak__, visibility("default")))
void* __loader_android_dlopen_ext(const char* filename,
                                  int flag,
                                  const android_dlextinfo* extinfo,
                                  const void* caller_addr);

void* android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo) {
  void* result = __loader_android_dlopen_ext(filename, flags, extinfo, __builtin_return_address(0));
  if (result) {
    fdsan_update_map();
  }
  return result;
}

void* dlopen(const char* filename, int flags) {
  void* result = __loader_android_dlopen_ext(filename, flags, nullptr, __builtin_return_address(0));
  if (result) {
    fdsan_update_map();
  }
  return result;
}

}  // extern "C"
