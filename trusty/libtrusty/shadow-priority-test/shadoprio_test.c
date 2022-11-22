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

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

#ifndef TRUSTY_MAX_CPUS
#define TRUSTY_MAX_CPUS (4)
#endif /* TRUSTY_MAX_CPUS */

static const char* dev_name = NULL;

static const char* shprio_srv_name = "com.android.kernel.busy-test";

static uint opt_repeat = 1;
static uint opt_silent = 0;
static bool opt_random = false;

static uint target_cpu_id = 0;

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

static void print_usage_and_exit(const char* prog, int exit_code) {
    fprintf(stderr, usage, prog);
    exit(exit_code);
}

static int wait_for_ack_message(int tipc_fd) {
    char tipc_msg_buf[sizeof(struct service_req_pkt)];
    ssize_t rc;

    memset(tipc_msg_buf, 0, sizeof(struct service_req_pkt));
    while (true) {
        rc = read(tipc_fd, tipc_msg_buf, sizeof(struct service_req_pkt));
        if (rc < 0) {
            perror("shadoprio_test:: read failed");
            return ERROR;
        }
        if (rc > 0) {
            if (tipc_msg_buf[0] == 'y') {
                break;
            } else {
                fprintf(stderr, "shadoprio_test::%s: Bad Ack response '%s'!\n", __func__,
                        tipc_msg_buf);
                fflush(stderr);
                return ERROR;
            }
        }
    }
    DBGTRC(45, "shadoprio_test:%s: got ack message.\n", __func__);
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
        target_cpu = rand() % cpu_count;
    } else {
        /* increment target_cpu_id for next call */
        target_cpu_id += 1;
        if (target_cpu_id >= cpu_count) {
            target_cpu_id = 0;
        }
    }
    return target_cpu;
}

static int execute_test(uint repeat) {
    int tipc_fd;
    int error;
    int ret;
    uint cpu_count;
    uint i;

    error = NO_ERROR;

#if VERIFY_WITH_DEBUGFS
    debugfs_init();
    cpu_count = debugfs_get_cpu_count(dbgfs_fp);
#else
    cpu_count = TRUSTY_MAX_CPUS;
#endif /* VERIFY_WITH_DEBUGFS */
    DBGTRC(15, "shadoprio_test::%s: cpu_count = %d\n", __func__, cpu_count);

    tipc_fd = tipc_connect(dev_name, shprio_srv_name);
    if (tipc_fd < 0) {
        fprintf(stderr, "shadoprio_test::%s: Failed to connect service '%s'!\n", __func__,
                shprio_srv_name);
        fflush(stderr);
        goto error_return;
    } else {
        DBGTRC(15, "shadoprio_test::%s: succeeded to connect service '%s', fd=%d.\n", __func__,
               shprio_srv_name, tipc_fd);
    }

    DBGTRC(15, "shadoprio_test::%s: repeat=%u\n", __func__, repeat);

    for (i = 0; i < repeat; i++) {
        struct service_req_pkt testdata;
        struct timespec now;

        testdata.service_req_id = SERVICE_REQ_SET_PRIORITY;
        testdata.cpu_id = get_target_cpu(cpu_count);
        testdata.priority = get_target_priority();

        ret = clock_gettime(CLOCK_REALTIME, &now);
        printf("@%ld.%ld req service set_priority cpu=%d priority=%d\n", (long)now.tv_sec,
               now.tv_nsec, testdata.cpu_id, testdata.priority);
        fflush(stdout);

        ret = write(tipc_fd, &testdata, sizeof(testdata));
        if (ret != sizeof(testdata)) {
            fprintf(stderr, "shadoprio_test::%s: error - not all of testdata was written ret=%d!\n",
                    __func__, ret);
            fflush(stderr);
            goto error_return;
        }
        DBGTRC(45, "shadoprio_test::%s: %d bytes written to tipc channel.\n", __func__, ret);

        ret = wait_for_ack_message(tipc_fd);
        if (ret != NO_ERROR) {
            goto error_return;
        }

#if VERIFY_WITH_DEBUGFS
        int shprio_set;
        int shprio_get;
        shprio_set = map_shadow_priority(priority);
        shprio_get = debugfs_get_shadow_priority(cpu_id);
        if (shprio_get != shprio_set) {
            DBGTRC(5, "shadoprio_test::%s: cpu_id=%d mismatch shprio_set=%d shprio_get=%d\n",
                   __func__, testdata.cpu_id, shprio_set, shprio_get);
        }
        printf("shadoprio_test::%s: iter=%d cpu_id=%d shprio_set=%d shprio_get=%d\n", __func__,
               (i + 1), testdata.cpu_id, shprio_set, shprio_get);
        fflush(stdout);
#else
        printf("shadoprio_test::%s: iter=%d cpu_id=%d priority=%d done.\n", __func__, (i + 1),
               testdata.cpu_id, testdata.priority);
        fflush(stdout);
#endif /* VERIFY_WITH_DEBUGFS */
    }

    printf("shadoprio_test::%s: test completed.\n", __func__);
    error = NO_ERROR;
    goto success_return;

error_return:
    error = ERROR;
success_return:
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

    rc = execute_test(opt_repeat);

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
