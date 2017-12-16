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

#include <android-base/logging.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "autosuspend_ops.h"

namespace android {
namespace libsuspend {

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
    char wakeup_count[20];
    int wakeup_count_len;
    int ret;

    LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": read wakeup_count";
    lseek(wakeup_count_fd, 0, SEEK_SET);
    wakeup_count_len =
        TEMP_FAILURE_RETRY(read(wakeup_count_fd, wakeup_count, sizeof(wakeup_count) - 1));
    if (wakeup_count_len < 0) {
        PLOG(ERROR) << "Error reading from " << SYS_POWER_WAKEUP_COUNT;
        return SUSPEND_RESULT_WAKECOUNT_ERROR;
    }

    if (wakeup_count_len == 0) {
        PLOG(ERROR) << "Empty wakeup count";
        return SUSPEND_RESULT_WAKECOUNT_ERROR;
    }

    // Add null termination
    wakeup_count[wakeup_count_len] = 0;
    LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": write " << wakeup_count << " to wakeup_count";
    ret = TEMP_FAILURE_RETRY(write(wakeup_count_fd, wakeup_count, wakeup_count_len));
    if (ret < 0) {
        PLOG(ERROR) << "Error writing to " << SYS_POWER_WAKEUP_COUNT;
        return SUSPEND_RESULT_WAKECOUNT_ERROR;
    }

    LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": write " << sleep_state << " to " << SYS_POWER_STATE;
    ret = TEMP_FAILURE_RETRY(write(state_fd, sleep_state, strlen(sleep_state)));
    bool success = ret >= 0;
    Suspend_Result ret_val = success ? SUSPEND_RESULT_SUCCESS : SUSPEND_RESULT_ATTEMPTED;

    void (*func)(bool success) = wakeup_func;
    if (func != NULL) {
        (*func)(success);
    }

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

        LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": wait";
        ret = sem_wait(&autosuspend_lockout);
        if (ret < 0) {
            LOG(ERROR) << "Error waiting on semaphore";
            continue;
        }

        if (do_suspend(mem_sleep_state) >= 0) {
            // Device attempted to suspend
            success = true;
        }

        LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": release sem";
        ret = sem_post(&autosuspend_lockout);
        if (ret < 0) {
            LOG(ERROR) << "Error releasing semaphore";
        }
    }
    return NULL;
}

static int autosuspend_wakeup_count_enable(void) {
    int ret;

    LOG(VERBOSE) << "autosuspend_wakeup_count_enable";

    ret = sem_post(&autosuspend_lockout);

    if (ret < 0) {
        LOG(ERROR) << "Error posting semaphore";
    }

    LOG(VERBOSE) << "autosuspend_wakeup_count_enable done";

    return ret;
}

static int autosuspend_wakeup_count_disable(void) {
    int ret;

    LOG(VERBOSE) << "autosuspend_wakeup_count_disable";
    ret = sem_wait(&autosuspend_lockout);

    if (ret < 0) {
        LOG(ERROR) << "Error waiting for semaphore";
    }

    LOG(VERBOSE) << "autosuspend_wakeup_count_disable done";
    return ret;
}

static void autosuspend_set_wakeup_callback(void (*func)(bool success)) {
    if (wakeup_func != NULL) {
        LOG(ERROR) << "Duplicate wakeup callback applied, keeping original";
        return;
    }
    wakeup_func = func;
}

struct autosuspend_ops autosuspend_wakeup_count_ops = {
    .enable = autosuspend_wakeup_count_enable,
    .disable = autosuspend_wakeup_count_disable,
    .set_wakeup_callback = autosuspend_set_wakeup_callback,
};

extern "C" {
struct autosuspend_ops* autosuspend_wakeup_count_init(void) {
    int ret;

    state_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_STATE, O_RDWR));
    if (state_fd < 0) {
        LOG(ERROR) << "Error opening " << SYS_POWER_STATE;
        goto err_open_state;
    }

    wakeup_count_fd = TEMP_FAILURE_RETRY(open(SYS_POWER_WAKEUP_COUNT, O_RDWR));
    if (wakeup_count_fd < 0) {
        LOG(ERROR) << "Error opening " << SYS_POWER_WAKEUP_COUNT;
        goto err_open_wakeup_count;
    }

    ret = sem_init(&autosuspend_lockout, 0, 0);
    if (ret < 0) {
        LOG(ERROR) << "Error creating semaphore";
        goto err_autosuspend_sem_init;
    }

    ret = pthread_create(&suspend_thread, NULL, suspend_thread_func, NULL);
    if (ret) {
        LOG(ERROR) << "Error creating thread";
        goto err_pthread_create;
    }

    LOG(INFO) << "Selected wakeup count";
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
}

}  // namespace libsuspend
}  // namespace android
