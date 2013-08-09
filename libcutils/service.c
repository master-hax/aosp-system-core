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

#include <cutils/properties.h>
#include <sched.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "cutils/service.h"

typedef bool (*predicate_t)(const char *service_name);

static bool service_wait_for_predicate(const char *service_name,
        predicate_t predicate, int timeout_sec);

static bool service_get_status(const char *service_name, char status[]);

static const char START_PROPERTY_NAME[] = "ctl.start";
static const char STOP_PROPERTY_NAME[] = "ctl.stop";
static const char STATUS_PROPERTY_PREFIX[] = "init.svc.";
static const char STARTED_RESULT_VALUE[] = "running";
static const char STOPPED_RESULT_VALUE[] = "stopped";

bool service_start(const char *service_name, const char *args,
        unsigned timeout_sec) {
    char start_command[PROPERTY_VALUE_MAX];

    strncpy(start_command, service_name, sizeof(start_command));
    if (args != NULL) {
        strncat(start_command, ":", sizeof(start_command));
        strncat(start_command, args, sizeof(start_command));
    }

    property_set(START_PROPERTY_NAME, start_command);
    sched_yield();

    return service_wait_for_predicate(service_name, service_is_running,
            timeout_sec);
}

bool service_stop(const char *service_name, unsigned timeout_sec) {
    property_set(STOP_PROPERTY_NAME, service_name);
    sched_yield();

    return service_wait_for_predicate(service_name, service_is_stopped,
            timeout_sec);
}

bool service_is_running(const char *service_name) {
    char status[PROPERTY_VALUE_MAX];
    return service_get_status(service_name, status) &&
            !strcmp(status, STARTED_RESULT_VALUE);
}

bool service_is_stopped(const char *service_name) {
    char status[PROPERTY_VALUE_MAX];
    return service_get_status(service_name, status) &&
            !strcmp(status, STOPPED_RESULT_VALUE);
}

static bool service_wait_for_predicate(const char *service_name,
        predicate_t predicate, int timeout_sec) {
    int count = timeout_sec * 10;

    while (count-- > 0) {
        if (predicate(service_name))
            return true;
        usleep(100000);
    }

    /* If timeout_sec == 0, the caller doesn't care about the predicate's
       success/failure. */
    return (timeout_sec == 0);
}

static bool service_get_status(const char *service_name, char status[]) {
    char status_property_name[PROPERTY_VALUE_MAX];
    const size_t size = sizeof(status_property_name);

    strncpy(status_property_name, STATUS_PROPERTY_PREFIX, size);
    strncat(status_property_name, service_name, size);

    return property_get(status_property_name, status, NULL) != 0;
}
