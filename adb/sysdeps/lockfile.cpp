/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "sysdeps/lockfile_private.h"

#include <chrono>
#include <string>
#include <thread>

#include <android-base/logging.h>

#include "adb_utils.h"
#include "sysdeps.h"

std::string default_lockfile_path() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adb.lock";
}

bool lockfile_acquire(const std::string& path, std::string* contents) {
    // Give up after ~2s.
    for (int i = 0; i < 20; ++i) {
        switch (lockfile_acquire_impl(path, contents)) {
            case LockfileImplResult::lock_acquired:
                return true;

            case LockfileImplResult::lock_already_held:
                return false;

            case LockfileImplResult::retry:
                adb_sleep_ms(100);
                continue;
        }
    }
    LOG(FATAL) << "failed to acquire lockfile";
    abort();
}
