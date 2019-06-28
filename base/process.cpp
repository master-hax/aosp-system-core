/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "android-base/process.h"

#include <dirent.h>

#include <memory>

#include "android-base/parseint.h"

using namespace std::literals;

namespace android {
namespace base {

bool AllPids(std::vector<pid_t>* pids) {
#if defined(__linux__)
  pids->clear();

  auto proc_dir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/proc"), closedir};
  if (!proc_dir) {
    return false;
  }

  dirent* de;
  while ((de = readdir(proc_dir.get())) != nullptr) {
    if (de->d_name == "."s || de->d_name == ".."s || de->d_type != DT_DIR) {
      continue;
    }

    pid_t pid;
    if (!ParseInt(de->d_name, &pid)) {
      continue;
    }

    pids->emplace_back(pid);
  }

  return true;
#else
  (void)pids;
  return false;
#endif
}

}  // namespace base
}  // namespace android
