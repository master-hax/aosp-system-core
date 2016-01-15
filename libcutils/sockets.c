/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <cutils/sockets.h>
#include <log/log.h>

#if !defined(_WIN32)

#if defined(__ANDROID__)
/* For the socket trust (credentials) check */
#include <private/android_filesystem_config.h>
#define __android_unused
#else
#define __android_unused __attribute__((__unused__))
#endif

bool socket_peer_is_trusted(int fd __android_unused)
{
#if defined(__ANDROID__)
    struct ucred cr;
    socklen_t len = sizeof(cr);
    int n = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len);

    if (n != 0) {
        ALOGE("could not get socket credentials: %s\n", strerror(errno));
        return false;
    }

    if ((cr.uid != AID_ROOT) && (cr.uid != AID_SHELL)) {
        ALOGE("untrusted userid on other end of socket: userid %d\n", cr.uid);
        return false;
    }
#endif

    return true;
}

int socket_close(cutils_socket_t sock) {
  return close(sock);
}

#else

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms741549(v=vs.85).aspx
// claims WSACleanup() should be called before program exit, but general
// consensus seems to be that it hasn't actually been necessary for a long time,
// likely since Windows 3.1. Additionally, trying to properly use WSACleanup()
// can be extremely tricky and cause deadlock when using threads or atexit().
//
// Both adb (1) and Chrome (2) purposefully avoid WSACleanup() with no issues.
// (1) https://android.googlesource.com/platform/system/core.git/+/master/adb/sysdeps_win32.cpp
// (2) https://code.google.com/p/chromium/codesearch#chromium/src/net/base/winsock_init.cc
bool initialize_sockets() {
    // There's no harm in calling WSAStartup() multiple times but no benefit
    // either, we may as well skip it after the first.
    static bool init_success = false;

    if (!init_success) {
        WSADATA wsaData;
        init_success = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
    }

    return init_success;
}

int socket_close(cutils_socket_t sock) {
    return closesocket(sock);
}

#endif
