/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include <string>

#include <android-base/file.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "services.h"
#include "sysdeps.h"
#include "transport.h"

void service_bootstrap_func(void* x) {
    stinfo* sti = reinterpret_cast<stinfo*>(x);
    adb_thread_setname(android::base::StringPrintf("service %d", sti->fd));
    sti->func(sti->fd, sti->cookie);
    free(sti);
}

int create_service_thread(void (*func)(int, void *), void *cookie)
{
    int s[2];
    if (adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return -1;
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

    stinfo* sti = reinterpret_cast<stinfo*>(malloc(sizeof(stinfo)));
    if (sti == nullptr) {
        fatal("cannot allocate stinfo");
    }
    sti->func = func;
    sti->cookie = cookie;
    sti->fd = s[1];

    if (!adb_thread_create(service_bootstrap_func, sti)) {
        free(sti);
        adb_close(s[0]);
        adb_close(s[1]);
        printf("cannot create service thread\n");
        return -1;
    }

    D("service thread started, %d:%d",s[0], s[1]);
    return s[0];
}

int service_to_fd_shared(const char* name, const atransport* transport) {
    int ret = -1;

    if(!strncmp(name, "tcp:", 4)) {
        int port = atoi(name + 4);
        name = strchr(name + 4, ':');
        if(name == 0) {
            std::string error;
            ret = network_loopback_client(port, SOCK_STREAM, &error);
            if (ret >= 0)
                disable_tcp_nagle(ret);
        } else {
#if ADB_HOST
            std::string error;
            ret = network_connect(name + 1, port, SOCK_STREAM, 0, &error);
#else
            return -1;
#endif
        }
#if !defined(_WIN32)   /* winsock doesn't implement unix domain sockets */
    } else if(!strncmp(name, "local:", 6)) {
        ret = socket_local_client(name + 6,
                ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    } else if(!strncmp(name, "localreserved:", 14)) {
        ret = socket_local_client(name + 14,
                ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    } else if(!strncmp(name, "localabstract:", 14)) {
        ret = socket_local_client(name + 14,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localfilesystem:", 16)) {
        ret = socket_local_client(name + 16,
                ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
#endif
    }
    if (ret >= 0) {
        close_on_exec(ret);
    }
    return ret;
}

