/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <errno.h>
#include <getopt.h>
#include <log/log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/busy_test/busy_test.h>
#include <trusty/tipc.h>

int busy_test_connect(const char* dev_name, int* fd) {
    int fd_tmp = tipc_connect(dev_name, BUSY_TEST_PORT);
    if (fd_tmp < 0) {
        fprintf(stderr, "failed to connect to '%s' app: %s\n", BUSY_TEST_PORT, strerror(-fd_tmp));
        return fd_tmp;
    }
    *fd = fd_tmp;
    return 0;
}

int busy_test_set_priority(int fd, uint32_t cpu, uint32_t priority) {
    struct {
        struct busy_test_req hdr;
        struct busy_test_set_priority_req set_priority;
    } req = {
            .hdr.cmd = BUSY_TEST_CMD_SET_PRIORITY,
            .hdr.reserved = 0,
            .set_priority.cpu = cpu,
            .set_priority.priority = priority,
    };

    int rc = write(fd, &req, sizeof(req));
    if (rc != (int)sizeof(req)) {
        ALOGE("unexpected number of bytes sent (%d) != expected (%zu)", rc, sizeof(req));
        return -EIO;
    }
    struct busy_test_resp resp = {};

    rc = read(fd, &resp, sizeof(resp));
    if (rc != (int)sizeof(resp)) {
        ALOGE("unexpected number of bytes received (%d) != expected (%zu)", rc, sizeof(resp));
        return -EIO;
    }
    if (resp.cmd != (req.hdr.cmd | BUSY_TEST_CMD_RESP_BIT)) {
        ALOGE("unexpected response command (%u) != expected (%u)", resp.cmd,
              req.hdr.cmd | BUSY_TEST_CMD_RESP_BIT);
        return -EIO;
    }
    if (resp.status != BUSY_TEST_NO_ERROR) {
        ALOGE("BUSY_TEST_CMD_SET_PRIORITY command failed (%d)", resp.status);
    }
    return resp.status;
}
