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

/* Functions to operate on native services managed by the init daemon. */

#ifndef __CUTILS_SERVICE_H__
#define __CUTILS_SERVICE_H__

#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/* Starts the service given by service_name. The arguments are space
 * separated and do not need to start with service_name. Returns true
 * if the service enters the "running" state before the timeout runs out,
 * returns false otherwise.
 *
 * This function will always return true if the timeout is 0.
 */
bool service_start(const char *service_name, const char *args,
    unsigned long timeout_ms);

/* Stops the service given by service_name. Returns true if the service
 * enters the "stopped" state before the timeout runs out, returns false
 * otherwise.
 *
 * This function will always return true if the timeout is 0.
 */
bool service_stop(const char *service_name, unsigned long timeout_ms);

bool service_is_running(const char *service_name);
bool service_is_stopped(const char *service_name);

__END_DECLS

#endif // __CUTILS_SERVICE_H__
