/*
 * Copyright (c) 2022, Google Inc. All rights reserved
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
    BUSY_TEST_ERR_UNKNOWN_CMD = 3,
    BUSY_TEST_ERR_INVALID_ARGS = 4,
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
 *                  (LOWEST_PRIORITY < priority <= HIGHEST_PRIORITY)
 *                  note that priority shall be strictly greater than
 *                  LOWEST_PRIORITY which is reserved for the IDLE thread.
 */
struct busy_test_set_priority_req {
    uint32_t cpu;
    uint32_t priority;
} __attribute__((__packed__));

#define BUSY_TEST_MAX_MSG_SIZE \
    (sizeof(struct busy_test_req) + sizeof(struct busy_test_set_priority_req)
