/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// #define LOG_NDEBUG 0

#define LOG_TAG "qtaguid"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cutils/qtaguid.h>
#include <log/log.h>

/* Load and link the libnetd_client method with qtaguid module. It is called
 * once per process.
 * TODO: Maybe we can find a way to do this one time and all processes can
 * directly use it later?
 */

class netdHandler {
  public:
    int (*netdTagSocket)(int, uint32_t, uid_t);
    int (*netdUntagSocket)(int);
    int (*netdSetCounterSet)(uint32_t, uid_t);
    int (*netdDeleteTagData)(uint32_t, uid_t);
};

netdHandler init(void) {
    char* error;
    netdHandler handler;
    void* netdClientHandle = dlopen("libnetd_client.so", RTLD_NOW);
    if (!netdClientHandle) {
        error = dlerror();
        ALOGE("Failed to open libnetd_client.so: %s", error);
        return handler;
    }

    dlerror();
    handler.netdTagSocket = (int (*)(int, uint32_t, uid_t))dlsym(netdClientHandle, "tagSocket");
    if (!handler.netdTagSocket) {
        error = dlerror();
        ALOGE("load netdTagSocket handler failed: %s", error);
    }

    handler.netdUntagSocket = (int (*)(int))dlsym(netdClientHandle, "untagSocket");
    if (!handler.netdUntagSocket) {
        error = dlerror();
        ALOGE("load netdUntagSocket handler failed: %s", error);
    }

    handler.netdSetCounterSet = (int (*)(uint32_t, uid_t))dlsym(netdClientHandle, "setCounterSet");
    if (!handler.netdSetCounterSet) {
        error = dlerror();
        ALOGE("load netdSetCounterSet handler failed: %s", error);
    }

    handler.netdDeleteTagData = (int (*)(uint32_t, uid_t))dlsym(netdClientHandle, "deleteTagData");
    if (!handler.netdDeleteTagData) {
        error = dlerror();
        ALOGE("load netdDeleteTagData handler failed: %s", error);
    }
    return handler;
}

static netdHandler qtaguidHandler = init();

int qtaguid_tagSocket(int sockfd, int tag, uid_t uid) {
    int res;

    // Check the socket fd passed to us is still valid before we load the netd
    // client. Pass a already closed socket fd to netd client may let netd open
    // the unix socket with the same fd number and pass it to server for
    // tagging.
    res = fcntl(sockfd, F_GETFD);
    if (res < 0) return res;

    ALOGV("Tagging socket %d with tag %u for uid %d", sockfd, tag, uid);

    res = qtaguidHandler.netdTagSocket(sockfd, tag, uid);

    return res;
}

int qtaguid_untagSocket(int sockfd) {
    int res;

    ALOGV("Untagging socket %d", sockfd);

    res = qtaguidHandler.netdUntagSocket(sockfd);

    return res;
}

int qtaguid_setCounterSet(int counterSetNum, uid_t uid) {
    int res;

    ALOGV("Setting counters to set %d for uid %d", counterSetNum, uid);

    res = qtaguidHandler.netdSetCounterSet(counterSetNum, uid);
    return res;
}

int qtaguid_deleteTagData(int tag, uid_t uid) {
    int res;

    ALOGV("Deleting tag data with tag %u for uid %d", tag, uid);

    res = qtaguidHandler.netdDeleteTagData(tag, uid);

    return res;
}
