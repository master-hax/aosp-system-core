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

#define MSEC_PER_SEC 1000
#define USEC_PER_MSEC 1000
#define USEC_PER_SEC (MSEC_PER_SEC * USEC_PER_MSEC)
#define POLL_PERIOD_USEC (100 * USEC_PER_MSEC)
#define POLL_PERIOD_PER_SEC (USEC_PER_SEC / POLL_PERIOD_USEC)

typedef bool (*predicate_t)(const char *service_name);

static bool service_wait_for_predicate(const char *service_name,
        predicate_t predicate, unsigned long timeout_sec);

static bool service_get_status(const char *service_name, char status[],
        size_t length);

static const char start_property_name[] = "ctl.start";
static const char stop_property_name[] = "ctl.stop";
static const char status_property_prefix[] = "init.svc.";
static const char started_result_value[] = "running";
static const char stopped_result_value[] = "stopped";

bool service_start(const char *service_name, const char *args,
        unsigned long timeout_sec) {
    char start_command[PROPERTY_VALUE_MAX];
    const size_t len = sizeof(start_command);

    if (args != NULL)
        snprintf(start_command, len, "%s:%s", service_name, args);
    else
        strlcpy(start_command, service_name, len);

    property_set(start_property_name, start_command);

    return service_wait_for_predicate(service_name, service_is_running,
            timeout_sec);
}

bool service_stop(const char *service_name, unsigned long timeout_sec) {
    property_set(stop_property_name, service_name);

    return service_wait_for_predicate(service_name, service_is_stopped,
            timeout_sec);
}

bool service_is_running(const char *service_name) {
    char status[PROPERTY_VALUE_MAX];

    return service_get_status(service_name, status, sizeof(status)) &&
            !strcmp(status, started_result_value);
}

bool service_is_stopped(const char *service_name) {
    char status[PROPERTY_VALUE_MAX];

    return service_get_status(service_name, status, sizeof(status)) &&
            !strcmp(status, stopped_result_value);
}

static bool service_wait_for_predicate(const char *service_name,
        predicate_t predicate, unsigned long timeout_sec) {
    unsigned long count = timeout_sec * POLL_PERIOD_PER_SEC;

    sched_yield();
    while (count-- > 0) {
        if (predicate(service_name))
            return true;
        usleep(POLL_PERIOD_USEC);
    }

    /* If timeout_sec == 0, the caller doesn't care about the predicate's
       success/failure. */
    return (timeout_sec == 0);
}

static bool service_get_status(const char *service_name, char status[],
        size_t length) {
    char status_property_name[PROPERTY_KEY_MAX];
    char status_value[PROPERTY_VALUE_MAX];

    snprintf(status_property_name, sizeof(status_property_name), "%s%s",
            status_property_prefix, service_name);

    if (property_get(status_property_name, status_value, NULL)) {
        strlcpy(status, status_value, length);
        return true;
    }

    return false;
}
