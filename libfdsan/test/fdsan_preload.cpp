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

#include <stdlib.h>

#include <gtest/gtest.h>

int main(int argc, char** argv) {
  if (!getenv("LD_PRELOAD")) {
#if defined(__LP64__)
    const char* lib_path = "/system/lib64/libfdsan.so";
#else
    const char* lib_path = "/system/lib/libfdsan.so";
#endif
    setenv("LD_PRELOAD", lib_path, 1);
    execve(argv[0], argv, environ);
  }

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
