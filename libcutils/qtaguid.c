/*
** Copyright 2011, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

// #define LOG_NDEBUG 0

#define LOG_TAG "qtaguid"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cutils/qtaguid.h>
#include <log/log.h>

/*
 * One per proccess.
 * Once the device is open, this process will have its socket tags tracked.
 * And on exit or untimely death, all socket tags will be removed.
 * A process can only open /dev/xt_qtaguid once.
 * It should not close it unless it is really done with all the socket tags.
 * Failure to open it will be visible when socket tagging will be attempted.
 */
pthread_once_t resTrackInitDone = PTHREAD_ONCE_INIT;

/* Load and link the libnetd_client method with qtaguid module. It is called
 * once per process.
 * TODO: Maybe we can find a way to do this one time and all processes can
 * directly use it later?
 */
void qtaguid_resTrack(void) {
    char* error;
    void* netdClientHandle = dlopen("libnetd_client.so", RTLD_NOW);
    if (!netdClientHandle) {
        ALOGE("Fail to open netd file\n");
        return;
    }
    dlerror();
    netdTagSocket = (int (*)(int, uint32_t, uid_t))dlsym(netdClientHandle, "tagSocket");
    error = dlerror();
    if (error != NULL) {
        ALOGE("load netdTagSocket handler failed: %s\n", error);
    }
    netdUntagSocket = (int (*)(int))dlsym(netdClientHandle, "untagSocket");
    error = dlerror();
    if (error != NULL) {
        ALOGE("load netdUntagSocket handler failed: %s\n", error);
    }
    netdSetCounterSet = (int (*)(uint32_t, uid_t))dlsym(netdClientHandle, "setCounterSet");
    error = dlerror();
    if (error != NULL) {
        ALOGE("load netdSetCounterSet handler failed: %s\n", error);
    }
    netdDeleteTagData = (int (*)(uint32_t, uid_t))dlsym(netdClientHandle, "deleteTagData");
    error = dlerror();
    if (error != NULL) {
        ALOGE("load netdDeleteTagData handler failed: %s\n", error);
    }
    netdSetPacifier = (int (*)(uint32_t))dlsym(netdClientHandle, "setPacifier");
    error = dlerror();
    if (error != NULL) {
        ALOGE("load setPacifier handler failed: %s\n", error);
    }
}

int qtaguid_tagSocket(int sockfd, int tag, uid_t uid) {
    int res;

    if (!netdTagSocket) pthread_once(&resTrackInitDone, qtaguid_resTrack);

    ALOGV("Tagging socket %d with tag %u for uid %d", sockfd, tag, uid);

    res = fcntl(sockfd, F_GETFD);
    if (res < 0) return res;
    res = netdTagSocket(sockfd, tag, uid);

    return res;
}

int qtaguid_untagSocket(int sockfd) {
    int res;

    ALOGV("Untagging socket %d", sockfd);

    if (!netdUntagSocket) pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdUntagSocket(sockfd);

    return res;
}

int qtaguid_setCounterSet(int counterSetNum, uid_t uid) {
    int res;

    ALOGV("Setting counters to set %d for uid %d", counterSetNum, uid);

    if (!netdSetCounterSet) pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdSetCounterSet(counterSetNum, uid);
    return res;
}

int qtaguid_deleteTagData(int tag, uid_t uid) {
    int res;

    ALOGV("Deleting tag data with tag %u for uid %d", tag, uid);

    if (!netdDeleteTagData) pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdDeleteTagData(tag, uid);

    return res;
}

int qtaguid_setPacifier(int on) {
    int res;

    if (!netdDeleteTagData) pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdSetPacifier(on);

    return res;
}
