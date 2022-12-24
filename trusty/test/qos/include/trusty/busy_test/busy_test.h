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

#define BUSY_TEST_PORT "com.android.kernel.busy-test"

/**
 * enum busy_test_cmd - command identifiers for busy_test interface
 * @BUSY_TEST_CMD_RESP_BIT:          message is a response
 * @BUSY_TEST_CMD_REQ_SHIFT:         number of bits used by
 * @BUSY_TEST_CMD_RESP_BIT
 * @BUSY_TEST_CMD_SET_PRIORITY:      set priorities of a pinned thread
 */
enum busy_test_cmd : uint32_t {
    BUSY_TEST_CMD_RESP_BIT = 1,
    BUSY_TEST_CMD_REQ_SHIFT = 1,

    BUSY_TEST_CMD_SET_PRIORITY = (1 << BUSY_TEST_CMD_REQ_SHIFT),
};

/**
 * enum busy_test_error - busy_test error codes
 * @BUSY_TEST_NO_ERROR:         no error
 * @BUSY_TEST_ERR_GENERIC:      busy test service internal error
 * @BUSY_TEST_ERR_TIMEOUT:      timeout when completing a request
 *                              in case of a set_priority request
 *                              timeout would occur if the cpu is
 *                              hotplugged.
 * @BUSY_TEST_ERR_UNKNOWN_CMD:  unknown or not implemented command
 * @BUSY_TEST_ERR_INVALID_ARGS: invalid args passed into the request
 */
enum busy_test_error : uint32_t {
    BUSY_TEST_NO_ERROR = 0,
    BUSY_TEST_ERR_GENERIC = 1,
    BUSY_TEST_ERR_TIMEOUT = 2,
    BUSY_TEST_ERR_NOT_READY = 3,
    BUSY_TEST_ERR_UNKNOWN_CMD = 4,
    BUSY_TEST_ERR_INVALID_ARGS = 5,
};

/**
 * struct busy_test_req - structure for busy_test requests
 * @cmd:            command identifier - one of &enum busy_test_cmd
 * @reserved:       must be 0
 */
struct busy_test_req {
    uint32_t cmd;
    uint32_t reserved;
} __attribute__((__packed__));

/**
 * struct busy_test_resp - structure for busy_test responses
 * @cmd: command identifier - %BUSY_TEST_CMD_RESP_BIT or'ed with a cmd in
 *                            one of &enum busy_test_cmd
 * @status: response status, one of &enum busy_test_error
 */
struct busy_test_resp {
    uint32_t cmd;
    uint32_t status;
} __attribute__((__packed__));

/**
 * struct busy_test_set_priority_req - arguments of %BUSY_TEST_CMD_SET_PRIORITY
 *                  requests
 * @cpu:            Cpu identifying the pinned thread
 *                  (0 <= cpu < SMP_MAX_CPUS)
 * @priority:       priority at which the pinned thread shall be set
 *                  ((LOWEST_PRIORITY+1) < priority < HIGHEST_PRIORITY)
 *                  note that priority shall be strictly greater than
 *                  (LOWEST_PRIORITY+1) which is reserved for the libsm idle
 *                  threads.
 *                  Priority shall also be strictly lower than HIGHEST_PRIORITY
 *                  which is reserved for the irq threads
 */
struct busy_test_set_priority_req {
    uint32_t cpu;
    uint32_t priority;
} __attribute__((__packed__));

#define BUSY_TEST_MAX_MSG_SIZE \
    (sizeof(struct busy_test_req) + sizeof(struct busy_test_set_priority_req)
