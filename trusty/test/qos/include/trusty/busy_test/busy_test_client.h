/*
 * Copyright 2022, The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <trusty/busy_test/busy_test.h>

extern "C" {

/**
 * busy_test_connect() - connect to the busy-test Trusted Application
 *
 * @dev_name:       device name for the Trusty driver
 * @fd:             file handle returned by tipc_connect
 *
 * Return:          0 if no error, tipc_connect error otherwise
 */
int busy_test_connect(const char* dev_name, int* fd);

/**
 * busy_test_set_priority() - set priority on a pinned thread
 *
 * @fd:             file handle returned by tipc_connect
 * @cpu:            cpu identifying the pinned thread
 *                  (0 <= cpu < SMP_MAX_CPUS)
 * @priority:       priority at which the pinned thread shall be set
 *                  ((LOWEST_PRIORITY+1) < priority < HIGHEST_PRIORITY)
 *                  note that priority shall be strictly greater than
 *                  (LOWEST_PRIORITY+1) which is reserved for the libsm idle
 *                  threads.
 *                  Priority shall also be strictly lower than HIGHEST_PRIORITY
 *                  which is reserved for the irq threads
 *
 * Return:          one of the value from &enum busy_test_error
 */
int busy_test_set_priority(int fd, uint32_t cpu, uint32_t priority);
}
