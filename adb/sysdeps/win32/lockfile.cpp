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

#include <windows.h>

#include <android-base/errors.h>
#include <android-base/logging.h>
#include <android-base/utf8.h>

#include "adb_utils.h"

HANDLE lockfile_handle = INVALID_HANDLE_VALUE;

static bool lockfile_create(const std::wstring& path, const std::string* contents) {
    int desired_access = GENERIC_READ | GENERIC_WRITE;
    int share_mode = FILE_SHARE_READ;
    SECURITY_ATTRIBUTES security_attributes = {
        .nLength = sizeof(security_attributes),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle = true,
    };
    int creation_disposition = CREATE_ALWAYS;
    int flags = FILE_FLAG_DELETE_ON_CLOSE;

    lockfile_handle = CreateFileW(path.c_str(), desired_access, share_mode, &security_attributes,
                                  creation_disposition, flags, nullptr);

    if (lockfile_handle == INVALID_HANDLE_VALUE) {
        LOG(INFO) << "lockfile already exists";
        return false;
    }

    // This is racy, but things should be fine if we retry if we read nothing.
    if (!LockFile(lockfile_handle, 0, 0, ~0, ~0)) {
        LOG(FATAL) << "failed to lock lockfile";
    }

    if (!WriteFile(lockfile_handle, contents->data(), contents->length(), nullptr, nullptr)) {
        LOG(FATAL) << "failed to write to lockfile";
    }

    if (!UnlockFile(lockfile_handle, 0, 0, ~0, ~0)) {
        LOG(FATAL) << "failed to unlock lockfile";
    }

    return true;
}

static LockfileImplResult lockfile_read(const std::wstring& path, std::string* contents) {
    int desired_access = GENERIC_READ;
    int share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    int creation_disposition = OPEN_EXISTING;
    int flags = 0;

    lockfile_handle = CreateFileW(path.c_str(), desired_access, share_mode, nullptr,
                                  creation_disposition, flags, nullptr);

    if (lockfile_handle == INVALID_HANDLE_VALUE) {
        unsigned long error = GetLastError();
        switch (error) {
            case ERROR_LOCK_VIOLATION:
                LOG(INFO) << "lockfile still locked, retrying";
                break;

            case ERROR_ACCESS_DENIED: {
                std::string path_utf8;
                android::base::WideToUTF8(path, &path_utf8);
                LOG(FATAL) << "access denied to lockfile " << path_utf8;
            }

            default:
                LOG(FATAL) << "unexpected error while attempting to open lockfile: "
                           << android::base::SystemErrorCodeToString(error);
        }
        return LockfileImplResult::retry;
    }

    char buf[4096];
    unsigned long bytes_read = 0;
    if (!ReadFile(lockfile_handle, buf, sizeof(buf), &bytes_read, nullptr)) {
        // File is locked, retry.
        LOG(WARNING) << "lockfile read failed, retrying";
        return LockfileImplResult::retry;
    }

    if (bytes_read == 0) {
        // We won the race with the file's creator, retry.
        LOG(WARNING) << "read empty lockfile, retrying";
        return LockfileImplResult::retry;
    }

    contents->assign(buf, bytes_read);
    return LockfileImplResult::lock_already_held;
}

LockfileImplResult lockfile_acquire_impl(const std::string& path, std::string* contents) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        LOG(FATAL) << "failed to encode lockfile path to UTF-16: " << path;
    }

    if (lockfile_create(path_wide, contents)) {
        LOG(INFO) << "lockfile created at " << path;
        return LockfileImplResult::lock_acquired;
    }

    return lockfile_read(path_wide, contents);
}
