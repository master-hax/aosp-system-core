/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <linux/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

int MaybeDowngrade() {
    int res = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
    if (res == -1)
      return 1;
    if (static_cast<unsigned long>(res) & PR_MTE_TCF_ASYNC)
      return 2;
    time_t t = time(nullptr);
    while (time(nullptr) - t < 100) {
      res = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
      if (static_cast<unsigned long>(res) & PR_MTE_TCF_ASYNC) {
        return 0;
      }
    }
    return 3;
}

int main(int argc, char** argv) {
  if (argc == 2 && strcmp(argv[1], "--check-downgrade") == 0) {
    return MaybeDowngrade();
  }
  volatile char* f = (char*)malloc(1);
  printf("%c\n", f[17]);
  char buf[1];
  read(1, buf, 1);
  return 0;
}
