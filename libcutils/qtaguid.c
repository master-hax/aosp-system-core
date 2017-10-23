/*
** Copyright 2017, The Android Open Source Project
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
        error = dlerror();
        ALOGE("Failed to open libnetd_client.so: %s", error);
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
}

int qtaguid_tagSocket(int sockfd, int tag, uid_t uid) {
    int res;

    // Check the socket fd passed to us is still valid before we load the netd
    // client. Pass a already closed socket fd to netd client may let netd open
    // the unix socket with the same fd number and pass it to server for
    // tagging.
    res = fcntl(sockfd, F_GETFD);
    if (res < 0) return res;

    pthread_once(&resTrackInitDone, qtaguid_resTrack);

    ALOGV("Tagging socket %d with tag %u for uid %d", sockfd, tag, uid);

    res = netdTagSocket(sockfd, tag, uid);

    return res;
}

int qtaguid_untagSocket(int sockfd) {
    int res;

    ALOGV("Untagging socket %d", sockfd);

    pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdUntagSocket(sockfd);

    return res;
}

int qtaguid_setCounterSet(int counterSetNum, uid_t uid) {
    int res;

    ALOGV("Setting counters to set %d for uid %d", counterSetNum, uid);

    pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdSetCounterSet(counterSetNum, uid);
    return res;
}

int qtaguid_deleteTagData(int tag, uid_t uid) {
    int res;

    ALOGV("Deleting tag data with tag %u for uid %d", tag, uid);

    pthread_once(&resTrackInitDone, qtaguid_resTrack);
    res = netdDeleteTagData(tag, uid);

    return res;
}

// Keep this native implementation for controlling qtaguid module here. This
// code should not be used by any services and apps.
// TODO: delete this code after the vts tests are fixed.

static const char* GLOBAL_PACIFIER_PARAM = "/sys/module/xt_qtaguid/parameters/passive";
static const char* TAG_PACIFIER_PARAM = "/sys/module/xt_qtaguid/parameters/tag_tracking_passive";

static int write_param(const char* param_path, const char* value) {
    int param_fd;
    int res;

    param_fd = TEMP_FAILURE_RETRY(open(param_path, O_WRONLY | O_CLOEXEC));
    if (param_fd < 0) {
        return -errno;
    }
    res = TEMP_FAILURE_RETRY(write(param_fd, value, strlen(value)));
    if (res < 0) {
        return -errno;
    }
    close(param_fd);
    return 0;
}

int qtaguid_setPacifier(int on) {
    const char* value;

    value = on ? "Y" : "N";
    if (write_param(GLOBAL_PACIFIER_PARAM, value) < 0) {
        return -errno;
    }
    if (write_param(TAG_PACIFIER_PARAM, value) < 0) {
        return -errno;
    }
    return 0;
}
