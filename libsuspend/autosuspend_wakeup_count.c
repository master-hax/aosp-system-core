/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "libsuspend"
//#define LOG_NDEBUG 0

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <log/log.h>

#include "autosuspend_ops.h"

#define SYS_POWER_STATE "/sys/power/state"
#define SYS_POWER_WAKEUP_COUNT "/sys/power/wakeup_count"

#define BASE_SLEEP_TIME 100000

// Return codes for do_suspend()
typedef enum suspend_result {
    SUSPEND_RESULT_WAKECOUNT_ERROR = -2,      // Suspend wakecount isn't correct
    SUSPEND_RESULT_MUTEX_NOT_AVAILABLE = -1,  // Suspend couldn't get mutex
    SUSPEND_RESULT_ATTEMPTED = 0,             // Suspend was attempted but didn't happen
    SUSPEND_RESULT_SUCCESS = 1,               // Suspend was successful
} Suspend_Result;

static int state_fd;
static int wakeup_count_fd;
static pthread_t suspend_thread;
static sem_t autosuspend_lockout;
static const char mem_sleep_state[] = "mem";
static const char disk_sleep_state[] = "disk";
static void (*wakeup_func)(bool success) = NULL;
static int sleep_time = BASE_SLEEP_TIME;

// Contains logic to suspend the device.
static Suspend_Result do_suspend(const char* sleep_state) {
    char buf[80];
    char wakeup_count[20];
    int wakeup_count_len;
    int ret;
    int ret_val;
    bool success = false;

    ALOGV("%s: read wakeup_count", __func__);
    lseek(wakeup_count_fd, 0, SEEK_SET);
    wakeup_count_len = TEMP_FAILURE_RETRY(read(wakeup_count_fd, wakeup_count, sizeof(wakeup_count)));
    if (wakeup_count_len < 0) {
        ALOGE("Error reading from %s", SYS_POWER_WAKEUP_COUNT);
        ret_val = SUSPEND_RESULT_WAKECOUNT_ERROR;
        goto exit;
    }

    if (wakeup_count_len == 0) {
        ALOGE("Empty wakeup count");
        ret_val = SUSPEND_RESULT_WAKECOUNT_ERROR;
        goto exit;
    }

    ALOGV("%s: write %*s to wakeup_count", __func__, wakeup_count_len, wakeup_count);
    ret = TEMP_FAILURE_RETRY(write(wakeup_count_fd, wakeup_count, wakeup_count_len));
    if (ret < 0) {
        ALOGE("Error writing to %s", SYS_POWER_WAKEUP_COUNT);
        ret_val = SUSPEND_RESULT_WAKECOUNT_ERROR;
        goto exit;
    }

    ALOGV("%s: write %s to %s", __func__, sleep_state, SYS_POWER_STATE);
    ret = TEMP_FAILURE_RETRY(write(state_fd, sleep_state, strlen(sleep_state)));
    success = ret >= 0;
    ret_val = success ? SUSPEND_RESULT_SUCCESS : SUSPEND_RESULT_ATTEMPTED;

    void (*func)(bool success) = wakeup_func;
    if (func != NULL) {
        (*func)(success);
    }

exit:
    return ret_val;
}

static void update_sleep_time(bool success) {
    if (success) {
        sleep_time = BASE_SLEEP_TIME;
        return;
    }
    // double sleep time after each failure up to one minute
    sleep_time = MIN(sleep_time * 2, 60000000);
}

static void* suspend_thread_func(void* arg __attribute__((unused))) {
    bool success = true;

    while (1) {
        char buf[80];
        int ret;

        update_sleep_time(success);
        usleep(sleep_time);
        success = false;

        ALOGV("%s: wait", __func__);
        ret = sem_wait(&autosuspend_lockout);
        if (ret < 0) {
            ALOGE("Error waiting on semaphore");
            continue;
        }

        if (do_suspend(mem_sleep_state) >= 0) {
            // Device attempted to suspend
            success = true;
        }

        ALOGV("%s: release sem", __func__);
        ret = sem_post(&autosuspend_lockout);
        if (ret < 0) {
            ALOGE("Error releasing semaphore");
        }
    }
    return NULL;
}

static int autosuspend_wakeup_count_enable(void) {
    char buf[80];
    int ret;

    ALOGV("autosuspend_wakeup_count_enable");

    ret = sem_post(&autosuspend_lockout);

    if (ret < 0) {
        ALOGE("Error posting semaphore");
    }

    ALOGV("autosuspend_wakeup_count_enable done");

    return ret;
}

static int autosuspend_wakeup_count_disable(void) {
    char buf[80];
    int ret;

    ALOGV("autosuspend_wakeup_count_disable");

    ret = sem_wait(&autosuspend_lockout);

    if (ret < 0) {
        ALOGE("Error waiting for semaphore");
    }

    ALOGV("autosuspend_wakeup_count_disable done");

    return ret;
}

static void autosuspend_set_wakeup_callback(void (*func)(bool success)) {
    if (wakeup_func != NULL) {
        ALOGE("Duplicate wakeup callback applied, keeping original");
        return;
    }
    wakeup_func = func;
}

struct autosuspend_ops autosuspend_wakeup_count_ops = {
    .enable = autosuspend_wakeup_count_enable,
    .disable = autosuspend_wakeup_count_disable,
    .set_wakeup_callback = autosuspend_set_wakeup_callback,
};

struct autosuspend_ops* autosuspend_wakeup_count_init(void) {
    int ret;
    char buf[80];

    state_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_STATE, O_RDWR));
    if (state_fd < 0) {
        ALOGE("Error opening %s", SYS_POWER_STATE);
        goto err_open_state;
    }

    wakeup_count_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_WAKEUP_COUNT, O_RDWR));
    if (wakeup_count_fd < 0) {
        ALOGE("Error opening %s", SYS_POWER_WAKEUP_COUNT);
        goto err_open_wakeup_count;
    }

    ret = sem_init(&autosuspend_lockout, 0, 0);
    if (ret < 0) {
        ALOGE("Error creating semaphore");
        goto err_autosuspend_sem_init;
    }

    ret = pthread_create(&suspend_thread, NULL, suspend_thread_func, NULL);
    if (ret) {
        ALOGE("Error creating thread");
        goto err_pthread_create;
    }

    ALOGI("Selected wakeup count");
    return &autosuspend_wakeup_count_ops;

err_pthread_create:
    sem_destroy(&autosuspend_lockout);
err_autosuspend_sem_init:
    close(wakeup_count_fd);
err_open_wakeup_count:
    close(state_fd);
err_open_state:
    return NULL;
}
