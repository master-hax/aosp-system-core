// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <android-base/file.h>

#if defined(WIN32)
#include <io.h>
#define access _access
#else
#include <unistd.h>
#endif

#include <thread>

namespace android {
namespace base {

using namespace std::literals;

// Wait at most |relative_timeout| milliseconds for |path| to exist. dirname(path)
// must already exist. For example, to wait on /dev/block/dm-6, /dev/block must
// be a valid directory.
bool WaitForFile(const std::string& path, const std::chrono::milliseconds relative_timeout) {
  auto start_time = std::chrono::steady_clock::now();

  while (true) {
    if (!access(path.c_str(), F_OK) || errno != ENOENT) return true;

    std::this_thread::sleep_for(50ms);

    auto now = std::chrono::steady_clock::now();
    auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
    if (time_elapsed > relative_timeout) return false;
  }
}

// Wait at most |relative_timeout| milliseconds for |path| to stop existing.
bool WaitForFileDeleted(const std::string& path, const std::chrono::milliseconds relative_timeout) {
  auto start_time = std::chrono::steady_clock::now();

  while (true) {
    if (access(path.c_str(), F_OK) && errno == ENOENT) return true;

    std::this_thread::sleep_for(50ms);

    auto now = std::chrono::steady_clock::now();
    auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
    if (time_elapsed > relative_timeout) return false;
  }
}

}  // namespace base
}  // namespace android
