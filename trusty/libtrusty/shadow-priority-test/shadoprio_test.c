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
#include <unistd.h>
#define __USE_GNU

#include <trusty/tipc.h>

#ifndef ERROR
#define ERROR (-1)
#endif
#ifndef NO_ERROR
#define NO_ERROR (0)
#endif

#define LOCAL_TRACE_LEVEL (0)

#define DBGTRC(_dbglvl_, _fmt_, ...)                           \
    do {                                                       \
        if ((!opt_silent) && (_dbglvl_ < LOCAL_TRACE_LEVEL)) { \
            printf(_fmt_, ##__VA_ARGS__);                      \
        }                                                      \
    } while (0)

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

#define MAX_DEBUGFS_LINE_SIZE (64)

#define TIPC_MAX_MSG_SIZE (64)
static char tipc_msg_buf[TIPC_MAX_MSG_SIZE];

static const char* dev_name = NULL;

static const char* shprio_srv_name = "com.android.trusty.shprio-test-srv";
static const char* shprio_debugfs_name = "/sys/kernel/debug/trusty-share/shadow-priority";

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

static void write_string(int fd, char* str) {
    int lenth;
    int sent;
    int i;

    lenth = strlen(str);
    for (i = 0;;) {
        sent = write(fd, &str[i], lenth);
        if (sent < 0) {
            perror("shadoprio_test:: write failed!");
            break;
        }
        i += sent;
        lenth -= sent;
        if (lenth < 1) {
            break;
        }
    }
}

static void send_set_message(int tipc_fd, uint cpu_id, uint shprio_set) {
    int msg_size;

    memset(tipc_msg_buf, 0, sizeof(tipc_msg_buf));
    sprintf(tipc_msg_buf, "cpu:%d prio:%d", cpu_id, shprio_set);

    msg_size = strlen(tipc_msg_buf);
    DBGTRC(15, "*** shadoprio_test:%s: msg_sz=%d msg='%s'\n", __func__, msg_size, tipc_msg_buf);

    write_string(tipc_fd, tipc_msg_buf);
}

static void send_exit_message(int tipc_fd, bool success) {
    int msg_size;

    memset(tipc_msg_buf, 0, sizeof(tipc_msg_buf));
    sprintf(tipc_msg_buf, "exit:%d", success ? 0 : 1);

    msg_size = strlen(tipc_msg_buf);
    DBGTRC(15, "*** shadoprio_test::%s: msg_sz=%d msg='%s'\n", __func__, msg_size, tipc_msg_buf);

    write_string(tipc_fd, tipc_msg_buf);
}

static int wait_for_ack_message(int tipc_fd) {
    ssize_t rc;

    memset(tipc_msg_buf, 0, TIPC_MAX_MSG_SIZE);
    rc = read(tipc_fd, tipc_msg_buf, TIPC_MAX_MSG_SIZE);
    if (rc < 0) {
        perror("shadoprio_test:: read failed");
        return ERROR;
    }
    if (tipc_msg_buf[0] != 'y') {
        fprintf(stderr, "shadoprio_test::%s: Bad Ack response '%s'!\n", __func__, tipc_msg_buf);
        return ERROR;
    }
    DBGTRC(15, "*** shadoprio_test:%s: got ack message.\n", __func__);
    return NO_ERROR;
}

static int parse_cpu_id(char* linebuf) {
    char* toks; /* start of token */
    char* toke; /* end of token */
    int cpu_id;
    char save;

    cpu_id = -1;
    toks = strchr(linebuf, '[');
    if (!toks) {
        return cpu_id;
    }
    toks++;

    toke = strchr(toks, ']');
    if (!toke) {
        return cpu_id;
    }
    save = *toke;
    *toke = '\0';

    cpu_id = atoi(toks);
    *toke = save;

    DBGTRC(75, "*** %s: cpu_id=%d\n", __func__, cpu_id);
    return cpu_id;
}

static char* find_token(char* buf, const char* token) {
    uint i;
    size_t tok_len;
    char* tok_pos;
    if ((!buf) || (!token)) {
        return NULL;
    }

    DBGTRC(65, "*** shadoprio_test::%s: token:'%s' buf:'%s'\n", __func__, token, buf);

    tok_len = strlen(token);
    if (tok_len < 1) {
        return NULL;
    }

    for (i = 0;; i++) {
        tok_pos = &buf[i];
        DBGTRC(95, "*** shadoprio_test::%s: tok_pos:'%s'\n", __func__, tok_pos);

        if (strncmp(tok_pos, token, tok_len) == 0) {
            DBGTRC(75, "*** shadoprio_test::%s: got a MATCH!!\n", __func__);
            return tok_pos;
        }
        if (strlen(tok_pos) <= tok_len) {
            break;
        }
    }
    return NULL;
}

static uint parse_shadow_priority(char* linebuf) {
    uint shprio;
    char* toks; /* start of token */

    DBGTRC(65, "*** shadoprio_test::%s: linebuf='%s'\n", __func__, linebuf);

    shprio = 4;
    toks = find_token(linebuf, "ask_priority=");
    if (!toks) {
        return shprio;
    }
    DBGTRC(65, "*** shadoprio_test::%s: tokpos='%s'\n", __func__, toks);

    toks += strlen("ask_priority=");
    shprio = atoi(toks);
    return shprio;
}

static uint get_shadow_priority(FILE* dbgfs_fp, uint cpu_id) {
    uint shprio;
    int rv;

    DBGTRC(55, "*** shadoprio_test::%s: cpu_id=%d\n", __func__, cpu_id);

    shprio = 4;
    while (true) {
        char* linebuf;
        ssize_t read_len;
        size_t read_max;

        linebuf = (char*)malloc(MAX_DEBUGFS_LINE_SIZE);
        read_max = MAX_DEBUGFS_LINE_SIZE;
        memset(linebuf, 0, read_max);
        read_len = getline(&linebuf, &read_max, dbgfs_fp);
        if (read_len <= 0) {
            free(linebuf);
            DBGTRC(65, "*** shadoprio_test::%s: read_len=%d\n", __func__, (int)read_len);
            break;
        }
        DBGTRC(55, "*** shadoprio_test::%s: buf='%s'\n", __func__, linebuf);

        rv = parse_cpu_id(linebuf);
        if (rv != cpu_id) {
            free(linebuf);
            DBGTRC(65, "*** shadoprio_test::%s: no match rv=%d cpu_id=%d\n", __func__, rv, cpu_id);
            continue;
        }

        DBGTRC(55, "*** shadoprio_test::%s: match rv=%d cpu_id=%d\n", __func__, rv, cpu_id);

        shprio = parse_shadow_priority(linebuf);
        free(linebuf);
        break;
    }
    return shprio;
}

static uint get_cpu_count(FILE* dbgfs_fp) {
    uint cpu_count;
    int rv;

    cpu_count = 0;

    while (true) {
        char* linebuf;
        ssize_t read_len;
        size_t read_max;

        linebuf = (char*)malloc(MAX_DEBUGFS_LINE_SIZE);
        read_max = MAX_DEBUGFS_LINE_SIZE;
        memset(linebuf, 0, read_max);
        read_len = getline(&linebuf, &read_max, dbgfs_fp);
        if (read_len <= 0) {
            free(linebuf);
            DBGTRC(75, "*** shadoprio_test::%s: read_len=%d\n", __func__, (int)read_len);
            break;
        }
        DBGTRC(75, "*** shadoprio_test::%s: buf: %s\n", __func__, linebuf);

        rv = parse_cpu_id(linebuf);
        free(linebuf);

        if (rv >= 0) {
            if (++rv > cpu_count) {
                cpu_count = rv;
            }
        }
    }
    return cpu_count;
}

static uint get_target_shprio(void) {
    /* TBD: Replace hardwired 3 with Max Value from the header file */
    uint target_shprio = (rand() % 3) + 1;
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
    FILE* dbgfs_fp;
    int tipc_fd;
    int error;
    int ret;
    uint cpu_count;
    uint i;

    error = NO_ERROR;

    dbgfs_fp = fopen(shprio_debugfs_name, "r");
    if (!dbgfs_fp) {
        fprintf(stderr, "shadoprio_test::%s: Failed to open '%s' for read!\n", __func__,
                shprio_debugfs_name);
        return error;
    }
    cpu_count = get_cpu_count(dbgfs_fp);
    DBGTRC(15, "*** shadoprio_test::%s: cpu_count = %d\n", __func__, cpu_count);
    fclose(dbgfs_fp);

    tipc_fd = tipc_connect(dev_name, shprio_srv_name);
    if (tipc_fd < 0) {
        fprintf(stderr, "shadoprio_test::%s: Failed to connect service '%s'!\n", __func__,
                shprio_srv_name);
        goto error_return;
    } else {
        DBGTRC(15, "*** shadoprio_test:: succeeded to connect service '%s', fd=%d.\n",
               shprio_srv_name, tipc_fd);
    }

    DBGTRC(15, "*** shadoprio_test::%s: repeat=%u\n", __func__, repeat);

    for (i = 0; i < repeat; i++) {
        int shprio_set;
        int shprio_get;
        uint cpu_id;

        cpu_id = get_target_cpu(cpu_count);
        shprio_set = get_target_shprio();
        send_set_message(tipc_fd, cpu_id, shprio_set);

        ret = wait_for_ack_message(tipc_fd);
        if (ret != NO_ERROR) {
            goto error_return;
        }

        dbgfs_fp = fopen(shprio_debugfs_name, "r");
        if (!dbgfs_fp) {
            fprintf(stderr, "shadoprio_test::%s: Failed to open '%s' for read!\n", __func__,
                    shprio_debugfs_name);
            goto error_return;
        }
        shprio_get = get_shadow_priority(dbgfs_fp, cpu_id);
        fclose(dbgfs_fp);
        if (shprio_get != shprio_set) {
            DBGTRC(5, "*** shadoprio_test::%s: cpu_id=%d mismatch shprio_set=%d shprio_get=%d\n",
                   __func__, cpu_id, shprio_set, shprio_get);
            goto test_value_error;
        }
        printf("### shadoprio_test::%s: iter=%d cpu_id=%d shprio_set=%d shprio_get=%d\n", __func__,
               (i + 1), cpu_id, shprio_set, shprio_get);
    }

    send_exit_message(tipc_fd, true);
    ret = wait_for_ack_message(tipc_fd);
    if (ret != NO_ERROR) {
        goto error_return;
    }

    printf("$$$ shadoprio_test::%s: test completed successfully.\n", __func__);
    error = NO_ERROR;
    goto success_return;

test_value_error:
    send_exit_message(tipc_fd, false);
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
