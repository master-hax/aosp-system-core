/*
 * Copyright 2013, The Android Open Source Project
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

#include <unistd.h>
#include <string.h>

#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <cutils/properties.h>

#include "cutils/service.h"

#define USEC_PER_MSEC 1000UL
#define POLL_PERIOD_USEC (100 * USEC_PER_MSEC)

#define SERVICE_CMD_START              "ctl.start"
#define SERVICE_CMD_STOP               "ctl.stop"
#define SERVICE_STATUS_PROPERTY_PREFIX "init.svc."
#define SERVICE_STATUS_RUNNING         "running"
#define SERVICE_STATUS_STOPPED         "stopped"

typedef bool (*predicate_t)(const char *service_name);

static bool service_wait_for_predicate(const char *service_name,
        predicate_t predicate, unsigned long timeout_ms);

static bool service_get_status(const char *service_name, char status[],
        size_t length);

bool service_start(const char *service_name, const char *args,
        unsigned long timeout_ms) {
    char start_command[PROPERTY_VALUE_MAX];
    const size_t len = sizeof(start_command);

    if (args != NULL) {
        if (snprintf(start_command, len, "%s:%s", service_name, args) >= len)
            return false;
    }
    else
        strlcpy(start_command, service_name, len);

    property_set(SERVICE_CMD_START, start_command);

    return service_wait_for_predicate(service_name, service_is_running,
            timeout_ms);
}

bool service_stop(const char *service_name, unsigned long timeout_ms) {
    property_set(SERVICE_CMD_STOP, service_name);

    return service_wait_for_predicate(service_name, service_is_stopped,
            timeout_ms);
}

bool service_is_running(const char *service_name) {
    char status[PROPERTY_VALUE_MAX];

    return service_get_status(service_name, status, sizeof(status)) &&
            !strcmp(status, SERVICE_STATUS_RUNNING);
}

bool service_is_stopped(const char *service_name) {
    char status[PROPERTY_VALUE_MAX];

    return service_get_status(service_name, status, sizeof(status)) &&
            !strcmp(status, SERVICE_STATUS_STOPPED);
}

static bool service_wait_for_predicate(const char *service_name,
        predicate_t predicate, unsigned long timeout_ms) {

    /* Calculate the number of times we should check the predicate based on our
       polling interval. If the user specifies a timeout that is not evenly
       divisible by our polling period, round up. */
    unsigned long count =
        (timeout_ms * USEC_PER_MSEC + POLL_PERIOD_USEC - 1) / POLL_PERIOD_USEC;

    sched_yield();
    while (count-- > 0) {
        if (predicate(service_name))
            return true;
        usleep(POLL_PERIOD_USEC);
    }

    /* If timeout_ms == 0, the caller doesn't care about the predicate's
       success/failure. */
    return (timeout_ms == 0);
}

static bool service_get_status(const char *service_name, char status[],
        size_t length) {
    char status_property_name[PROPERTY_KEY_MAX];
    char status_value[PROPERTY_VALUE_MAX];

    int len = snprintf(status_property_name, sizeof(status_property_name),
            "%s%s", SERVICE_STATUS_PROPERTY_PREFIX, service_name);

    if (len >= sizeof(status_property_name))
        return false;

    if (property_get(status_property_name, status_value, NULL)) {
        strlcpy(status, status_value, length);
        return true;
    }

    return false;
}
