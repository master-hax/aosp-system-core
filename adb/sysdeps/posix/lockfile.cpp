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

#include "sysdeps/lockfile.h"
#include "sysdeps/lockfile_private.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include "adb_utils.h"

using android::base::unique_fd;

static unique_fd& lockfile_fd = *new unique_fd();
static std::string& lockfile_path = *new std::string();

LockfileImplResult lockfile_acquire_impl(const std::string& path, std::string* contents) {
    // Try to open, and then try to create the lockfile.
    // It doesn't matter what order we do this in, so optimize for the common case.
    unique_fd fd(open(path.c_str(), O_RDWR | O_CLOEXEC));
    if (fd != -1) {
        // Because we create lockfiles by linking an already-locked file, this call should only fail
        // if the process that originally created the lockfile died.
        int rc = flock(fd, LOCK_EX | LOCK_NB);
        if (rc != -1) {
            // Delete the lockfile and try again.
            LOG(INFO) << "stale lockfile found, unlinking";
            if (unlink(path.c_str()) != 0 && errno != ENOENT) {
                PLOG(FATAL) << "failed to delete lockfile at " << path;
            }
            return LockfileImplResult::kRetry;
        }

        if (errno != EWOULDBLOCK) {
            PLOG(FATAL) << "failed to lock lockfile";
        }

        if (!android::base::ReadFdToString(fd.get(), contents)) {
            PLOG(FATAL) << "failed to read lockfile at " << path;
        }
        return LockfileImplResult::kLockAlreadyHeld;
    }

    std::string temp_file = path + "." + std::to_string(getpid());
    fd.reset(open(temp_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
    if (fd == -1) {
        PLOG(FATAL) << "failed to create temporary lockfile at " << temp_file;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        PLOG(FATAL) << "failed to lock temporary lockfile";
    }

    if (!android::base::WriteStringToFd(*contents, fd)) {
        PLOG(FATAL) << "failed to write to temporary lockfile at " << temp_file;
    }

    if (link(temp_file.c_str(), path.c_str()) != 0) {
        if (errno == EEXIST) {
            // We lost the race.
            return LockfileImplResult::kRetry;
        }
        PLOG(FATAL) << "failed to link lockfile";
    }

    if (unlink(temp_file.c_str()) != 0) {
        PLOG(FATAL) << "failed to unlink temporary lockfile " << temp_file;
    }

    lockfile_fd = std::move(fd);
    lockfile_path = path;
    return LockfileImplResult::kLockAcquired;
}

void lockfile_release() {
    if (lockfile_path.empty() || lockfile_fd.get() < 0) {
        LOG(FATAL) << "attempted to release non-held lockfile";
    }
    unlink(lockfile_path.c_str());
    lockfile_fd.reset();
    lockfile_path.clear();
}
