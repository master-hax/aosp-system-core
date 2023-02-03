/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/parseint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <vector>

#ifdef _WIN32
#include <android-base/utf8.h>
#include <direct.h>
#include <shlobj.h>
#else
#include <pwd.h>
#endif

#include "filesystem.h"

namespace {

int lock_file(int fd) {
#ifdef _WIN32
    HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    OVERLAPPED overlapped = {};
    const BOOL locked = LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0,
                                   MAXDWORD, MAXDWORD, &overlapped);
    return locked ? 0 : -1;
#else
    struct flock fl;
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    fl.l_pid    = getpid();
    return fcntl(fd, F_SETLKW, &fl) == -1;
#endif
}

}

// inspired by adb implementation:
// cs.android.com/android/platform/superproject/+/master:packages/modules/adb/adb_utils.cpp;l=275
std::string home() {
#ifdef _WIN32
    WCHAR path[MAX_PATH];
    const HRESULT hr = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path);
    if (FAILED(hr)) {
        return {};
    }
    std::string home_str;
    if (!android::base::WideToUTF8(path, &home_str)) {
        return {};
    }
    return home_str;
#else
    if (const char* const home = getenv("HOME")) {
        return home;
    }

    struct passwd pwent;
    struct passwd* result;
    int pwent_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (pwent_max == -1) {
        pwent_max = 16384;
    }
    std::vector<char> buf(pwent_max);
    int rc = getpwuid_r(getuid(), &pwent, buf.data(), buf.size(), &result);
    if (rc == 0 && result) {
        return result->pw_dir;
    }
#endif

    return {};
}

bool directory_exists(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == -1) {
        return false;
    }
    if ((st.st_mode & S_IFMT) != S_IFDIR) {
        return false;
    }
    return true;
}

bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool ensure_directory_exists(const std::string& directory_path) {
    if (directory_exists(directory_path)) {
        return true;
    }

    const int result =
#ifdef _WIN32
                       _mkdir(directory_path.c_str());
#else
                       mkdir(directory_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif

    return result == 0 || errno == EEXIST;
}

bool ensure_file_doesnt_exist(const std::string& path) {
    if (!file_exists(path)) {
        return true;
    }
    return remove(path.c_str()) == 0;
}

FileLock::FileLock(std::string path) {
    fd_ = open(path.c_str(), O_CREAT | O_WRONLY, 0644);
    const int result = lock_file(fd_);
    if (result != 0) {
        close(fd_);
        fd_ = -1;
    }
}

FileLock::~FileLock() {
    if (fd_ != -1) {
        close(fd_);
    }
}

bool FileLock::acquired() const {
    return fd_ != -1;
}