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

/**
 * DOC: Shpriotest
 *
 * Shpriotest interface provides a way for Android clients to request
 * Trusty thread priority services running on specific CPUs.
 *
 * Currently implemented protocol supports Android Client to make a
 * service request to set the priority of a shpriotest worker thread
 * running on a particular CPU, and then wait for an acknowledgement
 * status response.
 *
 * NOTE: This interface is shared between Android and Trusty.
 * There is a copy in each repository, which must be kept in sync.
 */

#define SHPRIOTEST_PORT "com.android.kernel.shprio-test"

/**
 * enum shpriotest_cmd - command identifiers for shpriotest interface
 * @SHPRIOTEST_CMD_RESP_BIT:          message is a response
 * @SHPRIOTEST_CMD_REQ_SHIFT:         number of bits used by @SHPRIOTEST_CMD_RESP_BIT
 * @SHPRIOTEST_CMD_SET_PRIORITY:      set thread priority on specified CPU
 * @SHPRIOTEST_CMD_EXIT_TEST:         Test has completed; test-server exit
 */
enum shpriotest_cmd {
    SHPRIOTEST_CMD_RESP_BIT = 1,
    SHPRIOTEST_CMD_REQ_SHIFT = 1,

    SHPRIOTEST_CMD_SET_PRIORITY = (1 << SHPRIOTEST_CMD_REQ_SHIFT),
    SHPRIOTEST_CMD_EXIT_TEST = (2 << SHPRIOTEST_CMD_REQ_SHIFT),
};

/**
 * enum shpriotest_error - shpriotest error codes
 * @SHPRIOTEST_NO_ERROR:             no error
 * @SHPRIOTEST_ERR_MSGSIZE_MISMATCH: unexpected message size
 * @SHPRIOTEST_ERR_UNKNOWN_CMD:      unknown or not implemented command
 * @SHPRIOTEST_ERR_INVALID_REQ:      Request arguments invalid or not supported
 * @SHPRIOTEST_ERR_TEST_FAILED:      for one reason or another
 */
enum shpriotest_error {
    SHPRIOTEST_NO_ERROR = 0,
    SHPRIOTEST_ERR_MSGSIZE_MISMATCH = 1,
    SHPRIOTEST_ERR_UNKNOWN_CMD = 2,
    SHPRIOTEST_ERR_INVALID_REQ = 3,
    SHPRIOTEST_ERR_TEST_FAILED = 4,
};

/**
 * struct shpriotest_req - common structure for shpriotest requests
 * @cmd:       command identifier - one of &enum shpriotest_cmd
 * @cpu_id:    identity of the CPU; must be >= 0 and < active cpu_count
 * @priority:  must be > 0 and < 31 (HIGHEST PRIORITY)
 * @exit_code: 0 or an error-code representing test failure
 */
struct shpriotest_req {
    uint32_t cmd;
    uint32_t cpu_id;
    uint32_t priority;
    uint32_t exit_code;
} __attribute__((__packed__));

/**
 * struct shpriotest_resp - common structure for shpriotest responses
 * @cmd: command identifier - %SHPRIOTEST_CMD_RESP_BIT or'ed with a cmd in
 *                            one of &enum shpriotest_cmd
 * @status: response status, one of &enum shpriotest_error
 */
struct shpriotest_resp {
    uint32_t cmd;
    uint32_t status;
    uint32_t reserved[2];
} __attribute__((__packed__));

#define SHPRIOTEST_MSG_SIZE (sizeof(struct shpriotest_req))
