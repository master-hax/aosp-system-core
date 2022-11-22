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

/*
 * In order to mutually influence the behavior of each other,
 * Linux and Trusty use a shared-memory based data-structure
 * that contains information such as per-CPU 'shadow-priority'.
 * A test is required to verify that, as trusty thread priorities
 * change on a particular CPU, it is correspondingly reflected
 * through 'shadow-priority' in the shared-memory. As such, the
 * test must have 2 components implemented as client-server pair.
 * A linux client test app can request the trusty-side test-server,
 * to set priority of the test thread to a specific value while
 * executing on a particular CPU. When the server thread responds
 * to this request, the linux client can verify the reflected
 * 'shadow-priority' by reading the value from the shared-memory.
 * This module implements the Linux-side client test app.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define __USE_GNU

#include <trusty/tipc.h>

#include "shadoprio_test.h"
#include "shpriotest.h"

static const char* dev_name = NULL;

static uint opt_repeat = 1;
static uint opt_silent = 0;
static bool opt_random = false;

static uint target_cpu_id = 1; /* spare cpu0 for server control thread */

static const char* usage =
        "Usage: %s [options]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -r, --repeat <cnt>    repeat count\n"
        "  -s, --silent          silent\n"
        "  -x, --random          choose cpu_id in a random order\n"
        "\n";

static const char* _sopts = "hsxr:";

/* clang-format off */
static const struct option _lopts[] =  {
    {"help",    no_argument,       0, 'h'},
    {"silent",  no_argument,       0, 's'},
    {"random",  no_argument,       0, 'x'},
    {"repeat",  required_argument, 0, 'r'},
    {0, 0, 0, 0}
};
/* clang-format on */

bool debug_silent(void) {
    return opt_silent ? true : false;
}

static void print_usage_and_exit(const char* prog, int exit_code) {
    fprintf(stderr, usage, prog);
    exit(exit_code);
}

static int wait_for_ack_message(int tipc_fd) {
    struct shpriotest_resp resp;
    int rc;

    memset(&resp, 0, sizeof(resp));
    while (true) {
        rc = read(tipc_fd, &resp, sizeof(resp));
        if (rc < 0) {
            perror("shadoprio_test:: read failed");
            return ERROR;
        }
        if (rc > 0) {
            if (rc != sizeof(resp)) {
                fprintf(stderr,
                        "shadoprio_test::%s: protocol failure recv'd size=%d expected=%d!\n",
                        __func__, rc, (int)sizeof(resp));
                fflush(stderr);
                return ERROR;
            }

            if (resp.status == SHPRIOTEST_NO_ERROR) {
                break;
            } else {
                fprintf(stderr, "shadoprio_test::%s: service failed cmd=%d, status='%d'!\n",
                        __func__, resp.cmd, resp.status);
                fflush(stderr);
                return ERROR;
            }
        }
    }
    DBGTRC(45, "shadoprio_test::%s: recv'd ack for cmd=%d from test server.\n", __func__, resp.cmd);
    return NO_ERROR;
}

static uint get_target_priority(void) {
    /* TBD: Replace hardwired 3 with Max Value from the header file */
    uint target_shprio = (rand() % 30) + 1;
    return target_shprio;
}

static uint get_target_cpu(uint cpu_count) {
    uint target_cpu = target_cpu_id;

    if (opt_random) {
        while (target_cpu == 0) {
            target_cpu = rand() % cpu_count;
        }
    } else {
        /* increment target_cpu_id for next call */
        if (++target_cpu_id >= cpu_count) {
            target_cpu_id = 1;
        }
    }
    return target_cpu;
}

static int send_set_priority_req(int tipc_fd, uint req_cpu_id, uint req_priority) {
    struct shpriotest_req req;
    struct timespec now;
    int ret;

    memset(&req, 0, sizeof(req));
    req.cmd = SHPRIOTEST_CMD_SET_PRIORITY;
    req.cpu_id = req_cpu_id;
    req.priority = req_priority;

    ret = clock_gettime(CLOCK_REALTIME, &now);
    printf("@%ld.%ld req service set_priority cpu=%d priority=%d\n", (long)now.tv_sec, now.tv_nsec,
           req.cpu_id, req.priority);
    fflush(stdout);

    ret = write(tipc_fd, &req, sizeof(req));
    if (ret != sizeof(req)) {
        fprintf(stderr, "shadoprio_test::%s: error - not all of req was sent ret=%d!\n", __func__,
                ret);
        fflush(stderr);
        return ERROR;
    }
    DBGTRC(45, "shadoprio_test::%s: sent %d bytes request cmd=%d cpu=%d priority=%d.\n", __func__,
           ret, req.cmd, req.cpu_id, req.priority);
    return NO_ERROR;
}

static void send_exit_test(int tipc_fd, uint err_code) {
    struct shpriotest_req req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.cmd = SHPRIOTEST_CMD_EXIT_TEST;
    req.exit_code = err_code;

    ret = write(tipc_fd, &req, sizeof(req));
    if (ret != sizeof(req)) {
        fprintf(stderr, "shadoprio_test::%s: error - not all of req was sent ret=%d!\n", __func__,
                ret);
        fflush(stderr);
    }
    DBGTRC(45, "shadoprio_test::%s: sent %d bytes request cmd=%d exit_code=%d.\n", __func__, ret,
           req.cmd, req.exit_code);
}

static int execute_test(uint repeat) {
    int tipc_fd;
    int error;
    int ret;
    uint shprio_set;
    uint shprio_get;
    uint cpu_count;
    uint i;

    error = ERROR;

    cpu_count = shprio_debugfs_get_cpu_count();
    DBGTRC(15, "shadoprio_test::%s: cpu_count = %d\n", __func__, cpu_count);

    tipc_fd = tipc_connect(dev_name, SHPRIOTEST_PORT);
    if (tipc_fd < 0) {
        fprintf(stderr, "shadoprio_test::%s: Failed to connect service '%s'!\n", __func__,
                SHPRIOTEST_PORT);
        fflush(stderr);
        return ERROR;
    } else {
        DBGTRC(15, "shadoprio_test::%s: succeeded to connect service '%s', fd=%d.\n", __func__,
               SHPRIOTEST_PORT, tipc_fd);
    }

    DBGTRC(15, "shadoprio_test::%s: repeat=%u\n", __func__, repeat);

    for (i = 0; i < repeat; i++) {
        uint req_cpu_id = get_target_cpu(cpu_count);
        uint req_priority = get_target_priority();

        ret = send_set_priority_req(tipc_fd, req_cpu_id, req_priority);
        if (ret != NO_ERROR) {
            goto test_wrapup;
        }
        ret = wait_for_ack_message(tipc_fd);
        if (ret != NO_ERROR) {
            goto test_wrapup;
        }

        shprio_set = shprio_debugfs_map_shadow_priority(req_priority);
        for (int i = 0; i < 3; i++) {
            /* we will make up to 3 attempts to see if there is
             * a match with the updated value in the shared-memory that
             * has been successfully picked up by the debugfs. */
            ret = shprio_debugfs_get_shadow_priority(req_cpu_id, &shprio_get);
            if (ret != NO_ERROR) {
                DBGTRC(5, "shadoprio_test::%s: failed to get shadow priority from debugfs.\n",
                       __func__);
                send_exit_test(tipc_fd, SHPRIOTEST_ERR_TEST_FAILED);
                goto test_wrapup;
            }
            if (shprio_get == shprio_set) {
                break;
            }
        }
        printf("shadoprio_test::%s: iter=%d cpu_id=%d shprio_set=%d shprio_get=%d\n", __func__,
               (i + 1), req_cpu_id, shprio_set, shprio_get);
        fflush(stdout);
    }

    error = NO_ERROR;
    send_exit_test(tipc_fd, error);
    printf("shadoprio_test::%s: test completed.\n", __func__);

test_wrapup:
    tipc_close(tipc_fd);
    return error;
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) break; /* done */

        switch (c) {
            case 'x':
                opt_random = true;
                break;

            case 's':
                opt_silent = true;
                break;

            case 'r':
                opt_repeat = atoi(optarg);
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;

            default:
                break;
        }
    }
}

int main(int argc, char** argv) {
    int rc = 0;

    parse_options(argc, argv);

    dev_name = TIPC_DEFAULT_DEVNAME;

    shprio_debugfs_init();

    rc = execute_test(opt_repeat);

    shprio_debugfs_fini();

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
