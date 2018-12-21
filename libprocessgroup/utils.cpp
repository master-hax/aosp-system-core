/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utils.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

using android::base::StringPrintf;

bool MkdirAndChown(const std::string& path, mode_t mode,
                   uid_t uid, gid_t gid) {
    if (mkdir(path.c_str(), mode) == -1 && errno != EEXIST) {
        return false;
    }

    if (chown(path.c_str(), uid, gid) == -1) {
        int saved_errno = errno;
        rmdir(path.c_str());
        errno = saved_errno;
        return false;
    }

    return true;
}

int GetTokens(char *str, const std::string& delim, char *tokens[], int tok_count) {
    int i = 0;
    char *p;

    p = strtok(str, delim.c_str());
    while (i < tok_count && p != NULL) {
        tokens[i] = p;
        p = strtok(NULL, " ,");
        i++;
    }
    return i;
}

void ReplaceAll(std::string &str, const std::string &from,
                const std::string &to) {
    for (size_t pos = 0; ; pos += to.length()) {
        pos = str.find(from, pos);
        if (pos == std::string::npos)
            break;
        str.erase(pos, from.length());
        str.insert(pos, to);
    }
}

bool IsAppDependentPath(const std::string &path) {
    return path.find("<uid>", 0) != std::string::npos ||
           path.find("<pid>", 0) != std::string::npos;
}

std::string ExpandAppDependentPath(const std::string& cg_path, const std::string& subgrp,
                       uid_t uid, pid_t pid) {
    std::string p = StringPrintf("%s/%s", cg_path.c_str(), subgrp.c_str());
    ReplaceAll(p, "<uid>", std::to_string(uid));
    ReplaceAll(p, "<pid>", std::to_string(pid));
    return p;
}

bool Chown(const std::string& path, uid_t uid, gid_t gid) {
    if (chown(path.c_str(), uid, gid) == -1) {
        int saved_errno = errno;
        rmdir(path.c_str());
        errno = saved_errno;
        return false;
    }

    return true;
}

int GetTid() {
#ifdef __ANDROID__
    return gettid();
#else
    return 0;
#endif
}

void set_timerslack_ns(bool timerslack_support, int tid, unsigned long slack) {
    // v4.6+ kernels support the /proc/<tid>/timerslack_ns interface.
    // TODO: once we've backported this, log if the open(2) fails.
    if (timerslack_support) {
        char buf[64];
        snprintf(buf, sizeof(buf), "/proc/%d/timerslack_ns", tid);
        int fd = open(buf, O_WRONLY | O_CLOEXEC);
        if (fd != -1) {
            int len = snprintf(buf, sizeof(buf), "%lu", slack);
            if (write(fd, buf, len) != len) {
                PLOG(ERROR) << "set_timerslack_ns write failed: "
                            << strerror(errno);
            }
            close(fd);
            return;
        }
    }

    // TODO: Remove when /proc/<tid>/timerslack_ns interface is backported.
    if ((tid == 0) || (tid == GetTid())) {
        if (prctl(PR_SET_TIMERSLACK, slack) == -1) {
            PLOG(ERROR) << "set_timerslack_ns prctl failed: "
                        << strerror(errno);
        }
    }
}

int add_tid_to_cgroup(int tid, int fd)
{
    // specialized itoa -- works for tid > 0
    char text[22];
    char *end = text + sizeof(text) - 1;
    char *ptr = end;
    *ptr = '\0';
    while (tid > 0) {
        *--ptr = '0' + (tid % 10);
        tid = tid / 10;
    }

    if (write(fd, ptr, end - ptr) < 0) {
        /*
         * If the thread is in the process of exiting,
         * don't flag an error
         */
        if (errno != ESRCH) {
            PLOG(ERROR) << "JoinGroup failed to write '"
                << ptr << "' (" << strerror(errno) << "); fd=" << fd;
            return -1;
        }
    }

    return 0;
}
