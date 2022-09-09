/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define __GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <BufferAllocator/BufferAllocatorWrapper.h>

#include <trusty/tipc.h>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

static const char *dev_name = NULL;
static const char *test_name = NULL;

static const char *uuid_name = "com.android.ipc-unittest.srv.uuid";
static const char *echo_name = "com.android.ipc-unittest.srv.echo";
static const char *ta_only_name = "com.android.ipc-unittest.srv.ta_only";
static const char *ns_only_name = "com.android.ipc-unittest.srv.ns_only";
static const char *datasink_name = "com.android.ipc-unittest.srv.datasink";
static const char *closer1_name = "com.android.ipc-unittest.srv.closer1";
static const char *closer2_name = "com.android.ipc-unittest.srv.closer2";
static const char *closer3_name = "com.android.ipc-unittest.srv.closer3";
static const char *main_ctrl_name = "com.android.ipc-unittest.ctrl";
static const char* receiver_name = "com.android.trusty.memref.receiver";

static const char* _sopts = "hsvDS:t:r:m:b:";
/* clang-format off */
static const struct option _lopts[] =  {
    {"help",    no_argument,       0, 'h'},
    {"silent",  no_argument,       0, 's'},
    {"variable",no_argument,       0, 'v'},
    {"dev",     required_argument, 0, 'D'},
    {"srv",     required_argument, 0, 'S'},
    {"repeat",  required_argument, 0, 'r'},
    {"burst",   required_argument, 0, 'b'},
    {"msgsize", required_argument, 0, 'm'},
    {"thread_cnt", required_argument, 0, 'T'},
    {0, 0, 0, 0}
};
/* clang-format on */

static const char* usage =
        "Usage: %s [options]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        device name\n"
        "  -S, --srv name        service name\n"
        "  -t, --test name       test to run\n"
        "  -r, --repeat cnt      repeat count\n"
        "  -b, --burst cnt       burst count\n"
        "  -m, --msgsize size    max message size\n"
        "  -v, --variable        variable message size\n"
        "  -s, --silent          silent\n"
        "  -T, --thread_cnt      number of threads for echo and writev tests\n"
        "\n";

static const char* usage_long =
        "\n"
        "The following tests are available:\n"
        "   connect      - connect to specified service, defaults to echo+datasink\n"
        "   connect_foo  - connect to non existing service\n"
        "   burst_write  - send messages to datasink service\n"
        "   echo         - send/receive messages to echo service\n"
        "   echo_async   - submit/retrieve several messages at a time to echo service\n"
        "   select       - test select call\n"
        "   blocked_read - test blocked read\n"
        "   closer1      - connection closed by remote (test1)\n"
        "   closer2      - connection closed by remote (test2)\n"
        "   closer3      - connection closed by remote (test3)\n"
        "   ta2ta-ipc    - execute TA to TA unittest\n"
        "   dev-uuid     - print device uuid\n"
        "   ta-access    - test ta-access flags\n"
        "   writev       - writev test (write-then-read pair)\n"
        "   writev_async - writev test (large transfer)\n"
        "   readv        - readv test\n"
        "   send-fd      - transmit dma_buf to trusty, use as shm\n"
        "   chan_interference   - ensure that filling one channel doesn't prevent use of another\n"
        "\n";

static uint opt_repeat  = 1;
static uint opt_msgsize = 32;
static uint opt_msgburst = 32;
static bool opt_variable = false;
static bool opt_silent = false;
static uint opt_thread_cnt = 1;
static char* srv_name = NULL;

static void print_usage_and_exit(const char *prog, int code, bool verbose)
{
    fprintf(stderr, usage, prog);
    if (verbose) fprintf(stderr, "%s", usage_long);
    exit(code);
}

static void parse_options(int argc, char **argv)
{
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) break; /* done */

        switch (c) {
            case 'D':
                dev_name = strdup(optarg);
                break;

            case 'S':
                srv_name = strdup(optarg);
                break;

            case 't':
                test_name = strdup(optarg);
                break;

            case 'v':
                opt_variable = true;
                break;

            case 'r':
                opt_repeat = atoi(optarg);
                break;

            case 'm':
                opt_msgsize = atoi(optarg);
                break;

            case 'b':
                opt_msgburst = atoi(optarg);
                break;

            case 's':
                opt_silent = true;
                break;

            case 'T':
                opt_thread_cnt = atoi(optarg);
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS, true);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE, false);
        }
    }
}

static int connect_test(uint repeat)
{
    uint i;
    int echo_fd;
    int dsink_fd;
    int custom_fd;

    if (!opt_silent) {
        printf("%s: repeat = %u\n", __func__, repeat);
    }

    for (i = 0; i < repeat; i++) {
        if (srv_name) {
            custom_fd = tipc_connect(dev_name, srv_name);
            if (custom_fd < 0) {
                fprintf(stderr, "Failed to connect to '%s' service\n", srv_name);
            }
            if (custom_fd >= 0) {
                tipc_close(custom_fd);
            }
        } else {
            echo_fd = tipc_connect(dev_name, echo_name);
            if (echo_fd < 0) {
                fprintf(stderr, "Failed to connect to '%s' service\n", "echo");
            }
            dsink_fd = tipc_connect(dev_name, datasink_name);
            if (dsink_fd < 0) {
                fprintf(stderr, "Failed to connect to '%s' service\n", "datasink");
            }

            if (echo_fd >= 0) {
                tipc_close(echo_fd);
            }
            if (dsink_fd >= 0) {
                tipc_close(dsink_fd);
            }
        }
    }

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int connect_foo(uint repeat)
{
    uint i;
    int fd;

    if (!opt_silent) {
        printf("%s: repeat = %u\n", __func__, repeat);
    }

    for (i = 0; i < repeat; i++) {
        fd = tipc_connect(dev_name, "foo");
        if (fd >= 0) {
            fprintf(stderr, "succeeded to connect to '%s' service\n", "foo");
            tipc_close(fd);
        }
    }

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}


static int closer1_test(uint repeat)
{
    uint i;
    int fd;

    if (!opt_silent) {
        printf("%s: repeat = %u\n", __func__, repeat);
    }

    for (i = 0; i < repeat; i++) {
        fd = tipc_connect(dev_name, closer1_name);
        if (fd < 0) {
            fprintf(stderr, "Failed to connect to '%s' service\n", "closer1");
            continue;
        }
        if (!opt_silent) {
            printf("%s: connected\n", __func__);
        }
        tipc_close(fd);
    }

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int closer2_test(uint repeat)
{
    uint i;
    int fd;

    if (!opt_silent) {
        printf("%s: repeat = %u\n", __func__, repeat);
    }

    for (i = 0; i < repeat; i++) {
        fd = tipc_connect(dev_name, closer2_name);
        if (fd < 0) {
            if (!opt_silent) {
                printf("failed to connect to '%s' service\n", "closer2");
            }
        } else {
            /* this should always fail */
            fprintf(stderr, "connected to '%s' service\n", "closer2");
            tipc_close(fd);
        }
    }

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int closer3_test(uint repeat)
{
    uint i, j;
    ssize_t rc;
    int fd[4];
    char buf[64];

    if (!opt_silent) {
        printf("%s: repeat = %u\n", __func__, repeat);
    }

    for (i = 0; i < repeat; i++) {
        /* open 4 connections to closer3 service */
        for (j = 0; j < 4; j++) {
            fd[j] = tipc_connect(dev_name, closer3_name);
            if (fd[j] < 0) {
                fprintf(stderr, "fd[%d]: failed to connect to '%s' service\n", j, "closer3");
            } else {
                if (!opt_silent) {
                    printf("%s: fd[%d]=%d: connected\n", __func__, j, fd[j]);
                }
                memset(buf, i + j, sizeof(buf));
                rc = write(fd[j], buf, sizeof(buf));
                if (rc != sizeof(buf)) {
                    if (!opt_silent) {
                        printf("%s: fd[%d]=%d: write returned  = %zd\n", __func__, j, fd[j], rc);
                    }
                    perror("closer3_test: write");
                }
            }
        }

        /* sleep a bit */
        sleep(1);

        /* It is expected that they will be closed by remote */
        for (j = 0; j < 4; j++) {
            if (fd[j] < 0) continue;
            rc = write(fd[j], buf, sizeof(buf));
            if (rc != sizeof(buf)) {
                if (!opt_silent) {
                    printf("%s: fd[%d]=%d: write returned = %zd\n", __func__, j, fd[j], rc);
                }
                perror("closer3_test: write");
            }
        }

        /* then they have to be closed by remote */
        for (j = 0; j < 4; j++) {
            if (fd[j] >= 0) {
                tipc_close(fd[j]);
            }
        }
    }

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int channel_interference_test(uint repeat, uint msgsz, bool var) {
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    int datasink_fd = -1;

    char tx_buf[msgsz];

    echo_fd = tipc_connect(dev_name, echo_name);
    if (echo_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, echo_name);
        return echo_fd;
    }

    datasink_fd = tipc_connect(dev_name, datasink_name);
    if (datasink_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, echo_name);
        return datasink_fd;
    }

    /* make read/write not block */
    rc = fcntl(echo_fd, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "fcntl non-blocking mode failed on 'echo' (%d)\n", rc == -1 ? -errno : rc);
    }
    rc = fcntl(datasink_fd, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "fcntl non-blocking mode failed on 'datasink' (%d)\n",
                rc == -1 ? -errno : rc);
    }

    int i;
    uint no_tx_cnt = 0;
    for (i = 0; i < repeat; i++) {
        msg_len = msgsz;
        if (var && msgsz) {
            msg_len = rand() % msgsz;
        }

        /* 1) burst write until EAGAIN indicates channel is full */
        unsigned int tx_cnt = 0;
        for (; tx_cnt < 1000; tx_cnt++) {
            /* embed counter into message */
            *((unsigned int*)tx_buf) = tx_cnt;

            /* send */
            rc = write(echo_fd, tx_buf, msg_len);
            if (rc == -1 && errno == EAGAIN) {
                break;  // finished
            } else if ((size_t)rc != msg_len) {
                fprintf(stderr, "write error (%d) msg_len (%zu)\n", rc == -1 ? -errno : rc,
                        msg_len);
                return 1;
            }
        }

        /* 2) immediately send on another channel to ensure it is not blocked */
        if (tx_cnt > 0) {
            rc = write(datasink_fd, tx_buf, msg_len);
            fprintf(stderr, "%s: %d messages sent to 'echo' before EAGAIN\n", __func__, tx_cnt);
            if ((size_t)rc != msg_len) {
                fprintf(stderr, "%s: after %d/%d write to 'echo' (%d)\n", __func__, i, repeat,
                        rc == -1 ? -errno : rc);
                break;
            }
        } else {
            no_tx_cnt++;
        }
    }

    fprintf(stderr, "%s: closing echo channel\n", __func__);
    tipc_close(echo_fd);
    fprintf(stderr, "%s: closing datasink channel\n", __func__);
    tipc_close(datasink_fd);

    if (rc == msg_len || i >= repeat) {
        printf("%s: done\n", __func__);
    } else {
        printf("%s: failed (%d)\n", __func__, errno);
        return -errno;  // test failed
    }

    return 0;
}

static int _echo_test_async(uint repeat, uint msgsz, bool var, int seed) {
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;

    /* enforce lower bound for msg size to allow for order verification */
    if (msgsz < sizeof(unsigned int)) {
        msgsz = sizeof(unsigned int);
    }

    char tx_buf[msgsz];
    char rx_buf[msgsz];

    if (!opt_silent) {
        fprintf(stderr, "%s: repeat %u: msgsz %u: variable %s\n", __func__, repeat, msgsz,
                var ? "true" : "false");
    }

    const char* service_name = echo_name;
    if (srv_name) {
        service_name = srv_name;
    }

    echo_fd = tipc_connect(dev_name, service_name);
    if (echo_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, service_name);
        return echo_fd;
    }

    /* make read/write not block */
    rc = fcntl(echo_fd, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "fcntl non-blocking mode failed (%d)\n", rc == -1 ? -errno : rc);
    }

    /* set up and run a loop that reads and/or writes based on poll results */
    int tx_cnt = repeat;
    int rx_cnt = tx_cnt;
    bool abort_test = false;
    unsigned int rx_this_loop, tx_this_loop;
    unsigned int ceiling_rx_this_loop = 0, ceiling_tx_this_loop = 0;
    float acc_rx_per_loop = 0.0f, acc_tx_per_loop = 0.0f;
    int rx_loop_cnt = 0, tx_loop_cnt = 0;
    while (!abort_test && (tx_cnt >= 0 || rx_cnt >= 0)) {
        rx_this_loop = tx_this_loop = 0;

        /* send messages until all buffers are full */
        while (tx_cnt >= 0) {
            /* calculate variable length if applicable */
            msg_len = msgsz;
            if (var && msgsz) {
                msg_len = rand() % msgsz;
            }

            /* embed counter into message */
            *((unsigned int*)tx_buf) = tx_cnt + seed;

            /* embed length into message for verification of variable len */
            *((unsigned int*)tx_buf + sizeof(unsigned int)) = msg_len;

            /* send */
            rc = write(echo_fd, tx_buf, msg_len);
            if (rc == -1 && errno == EAGAIN) {
                break;  // try again later
            } else if ((size_t)rc != msg_len) {
                fprintf(stderr, "write error (%d) msg_len (%zu)\n", rc == -1 ? -errno : rc,
                        msg_len);
                abort_test = true;
                break;
            }
            tx_cnt--;
            tx_this_loop++;
        }

        /* drain all messages */
        while (rx_cnt >= 0) {
            rc = read(echo_fd, rx_buf, sizeof(rx_buf));
            if (rc == -1 && errno == EAGAIN) {
                break;  // try again later
            }
            if (rc < 0) {
                fprintf(stderr, "read error (%d)\n", rc == -1 ? -errno : rc);
                abort_test = true;
                break;
            }

            msg_len = *((unsigned int*)rx_buf + sizeof(unsigned int));
            if ((size_t)rc != msg_len) {
                fprintf(stderr, "%d: data truncated (%zu vs. %zu)\n", seed, rc, msg_len);
                abort_test = true;
                break;
            }

            /* verify order */
            unsigned int test_cnt = *(unsigned int*)rx_buf;
            if ((rx_cnt + seed) != test_cnt) {
                fprintf(stderr, "%d: data mismatch rx_cnt= %d, test_cnt= %d\n", seed, rx_cnt,
                        test_cnt);
                abort_test = true;
                break;
            }

            rx_cnt--;
            rx_this_loop++;
        }

        if (tx_this_loop > ceiling_tx_this_loop) {
            ceiling_tx_this_loop = tx_this_loop;
        }
        if (rx_this_loop > ceiling_rx_this_loop) {
            ceiling_rx_this_loop = rx_this_loop;
        }
        if (tx_this_loop > 0) {
            acc_tx_per_loop += tx_this_loop;
            ++tx_loop_cnt;
        }
        if (rx_this_loop > 0) {
            acc_rx_per_loop += rx_this_loop;
            ++rx_loop_cnt;
        }
    }

    tipc_close(echo_fd);

    printf("%d: ceiling tx= %d, rx= %d\n", seed, ceiling_tx_this_loop, ceiling_rx_this_loop);

    if (!opt_silent) {
        printf("%s: seed= %d done; avg per loop: tx= %.3f (%d), rx= %.3f (%d)\n", __func__, seed,
               acc_tx_per_loop / tx_loop_cnt, tx_loop_cnt, acc_rx_per_loop / rx_loop_cnt,
               rx_loop_cnt);
    }

    return (rx_cnt <= 0 && tx_cnt <= 0) ? 0 : (rc == -1 ? -errno : -1);
}

static int _echo_test(uint repeat, uint msgsz, bool var, uint seed) {
    uint i;
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    char tx_buf[msgsz];
    char rx_buf[msgsz];
    int ret = 0;
    (void)seed;

    if (!opt_silent) {
        printf("%s: repeat %u: msgsz %u: variable %s\n", __func__, repeat, msgsz,
               var ? "true" : "false");
    }

    const char* service_name = echo_name;
    if (srv_name) {
        service_name = srv_name;
    }

    echo_fd = tipc_connect(dev_name, service_name);
    if (echo_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, echo_name);
        return echo_fd;
    }

    for (i = 0; i < repeat; i++) {
        msg_len = msgsz;
        if (var && msgsz) {
            msg_len = rand() % msgsz;
        }

        memset(tx_buf, i + 1, msg_len);

        rc = write(echo_fd, tx_buf, msg_len);
        if ((size_t)rc != msg_len) {
            perror("echo_test: write");
            ret = -1;
            break;
        }

        rc = read(echo_fd, rx_buf, msg_len);
        if (rc < 0) {
            perror("echo_test: read");
            ret = -1;
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "data truncated (%zu vs. %zu)\n", rc, msg_len);
            continue;
        }

        if (memcmp(tx_buf, rx_buf, (size_t)rc)) {
            fprintf(stderr, "data mismatch\n");
            continue;
        }
    }

    tipc_close(echo_fd);

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return ret;
}

typedef struct {
    uint repeat;
    uint msgsz;
    uint seed;  // for variation between concurrent threads
    int result;
    bool var;
    bool async;
} threaded_test_args_t;

void* echo_test_thread(void* arg) {
    threaded_test_args_t* et = (threaded_test_args_t*)arg;

    if (et->async) {
        et->result = _echo_test_async(et->repeat, et->msgsz, et->var, et->seed);
    } else {
        et->result = _echo_test(et->repeat, et->msgsz, et->var, et->seed);
    }

    return NULL;
}

typedef struct {
    threaded_test_args_t args;
    pthread_t t;
} threaded_test_info_t;

static int threaded_test(void* (*thread_func)(void*), uint thread_cnt, const uint repeat,
                         const uint msgsz, const bool var, const bool async) {
    threaded_test_info_t tinfo[thread_cnt];
    int ret = 0;

    for (int i = 0; i < thread_cnt; i++) {
        tinfo[i].args.repeat = repeat;
        tinfo[i].args.msgsz = msgsz;
        tinfo[i].args.var = var;
        tinfo[i].args.async = async;
        tinfo[i].args.seed = 100000 * i;

        ret = pthread_create(&tinfo[i].t, NULL, thread_func, &tinfo[i].args);
        if (ret != 0) {
            printf("%s: %s\n", __func__, strerror(ret));
            return 1;
        }
    }

    ret = 0;
    for (int i = 0; i < thread_cnt; i++) {
        pthread_join(tinfo[i].t, NULL);
        if (tinfo[i].args.result != 0) {
            fprintf(stderr, "thread #%d failed (%d)\n", i, tinfo[i].args.result);
            ret = 1;
        }
    }

    return ret;
}

static int burst_write_test(uint repeat, uint msgburst, uint msgsz, bool var)
{
    int fd;
    uint i, j;
    ssize_t rc;
    size_t msg_len;
    char tx_buf[msgsz];

    if (!opt_silent) {
        printf("%s: repeat %u: burst %u: msgsz %u: variable %s\n", __func__, repeat, msgburst,
               msgsz, var ? "true" : "false");
    }

    for (i = 0; i < repeat; i++) {
        fd = tipc_connect(dev_name, datasink_name);
        if (fd < 0) {
            fprintf(stderr, "Failed to connect to '%s' service\n", "datasink");
            break;
        }

        for (j = 0; j < msgburst; j++) {
            msg_len = msgsz;
            if (var && msgsz) {
                msg_len = rand() % msgsz;
            }

            memset(tx_buf, i + 1, msg_len);
            rc = write(fd, tx_buf, msg_len);
            if ((size_t)rc != msg_len) {
                perror("burst_test: write");
                break;
            }
        }

        tipc_close(fd);
    }

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}


static int _wait_for_msg(int fd, uint msgsz, int timeout)
{
    int rc;
    fd_set rfds;
    uint msgcnt = 0;
    char rx_buf[msgsz];
    struct timeval tv;

    if (!opt_silent) {
        printf("waiting (%d) for msg\n", timeout);
    }

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    for (;;) {
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);

        if (rc == 0) {
            if (!opt_silent) {
                printf("select timedout\n");
            }
            break;
        }

        if (rc == -1) {
            perror("select_test: select");
            return rc;
        }

        rc = read(fd, rx_buf, sizeof(rx_buf));
        if (rc < 0) {
            perror("select_test: read");
            return rc;
        } else {
            if (rc > 0) {
                msgcnt++;
            }
        }
    }

    if (!opt_silent) {
        printf("got %u messages\n", msgcnt);
    }

    return 0;
}


static int select_test(uint repeat, uint msgburst, uint msgsz)
{
    int fd;
    uint i, j;
    ssize_t rc;
    char tx_buf[msgsz];

    if (!opt_silent) {
        printf("%s: repeat %u\n", __func__, repeat);
    }

    fd = tipc_connect(dev_name, echo_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "echo");
        return fd;
    }

    for (i = 0; i < repeat; i++) {
        _wait_for_msg(fd, msgsz, 1);

        if (!opt_silent) {
            printf("sending burst: %u msg\n", msgburst);
        }

        for (j = 0; j < msgburst; j++) {
            memset(tx_buf, i + j, msgsz);
            rc = write(fd, tx_buf, msgsz);
            if ((size_t)rc != msgsz) {
                perror("burst_test: write");
                break;
            }
        }
    }

    tipc_close(fd);

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int blocked_read_test(uint repeat)
{
    int fd;
    uint i;
    ssize_t rc;
    char rx_buf[512];

    if (!opt_silent) {
        printf("%s: repeat %u\n", __func__, repeat);
    }

    fd = tipc_connect(dev_name, echo_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "echo");
        return fd;
    }

    for (i = 0; i < repeat; i++) {
        rc = read(fd, rx_buf, sizeof(rx_buf));
        if (rc < 0) {
            perror("select_test: read");
            break;
        } else {
            if (!opt_silent) {
                printf("got %zd bytes\n", rc);
            }
        }
    }

    tipc_close(fd);

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int ta2ta_ipc_test(void)
{
    enum test_message_header {
        TEST_PASSED = 0,
        TEST_FAILED = 1,
        TEST_MESSAGE = 2,
    };

    int fd;
    int ret;
    unsigned char rx_buf[256];

    if (!opt_silent) {
        printf("%s:\n", __func__);
    }

    fd = tipc_connect(dev_name, main_ctrl_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "main_ctrl");
        return fd;
    }

    /* Wait for tests to complete and read status */
    while (true) {
        ret = read(fd, rx_buf, sizeof(rx_buf));
        if (ret <= 0 || ret >= (int)sizeof(rx_buf)) {
            fprintf(stderr, "%s: Read failed: %d\n", __func__, ret);
            tipc_close(fd);
            return -1;
        }

        if (rx_buf[0] == TEST_PASSED) {
            break;
        } else if (rx_buf[0] == TEST_FAILED) {
            break;
        } else if (rx_buf[0] == TEST_MESSAGE) {
            write(STDOUT_FILENO, rx_buf + 1, ret - 1);
        } else {
            fprintf(stderr, "%s: Bad message header: %d\n", __func__, rx_buf[0]);
            break;
        }
    }

    tipc_close(fd);

    return rx_buf[0] == TEST_PASSED ? 0 : -1;
}

typedef struct uuid
{
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_and_node[8];
} uuid_t;

static void print_uuid(const char *dev, uuid_t *uuid)
{
    printf("%s:", dev);
    printf("uuid: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", uuid->time_low,
           uuid->time_mid, uuid->time_hi_and_version, uuid->clock_seq_and_node[0],
           uuid->clock_seq_and_node[1], uuid->clock_seq_and_node[2], uuid->clock_seq_and_node[3],
           uuid->clock_seq_and_node[4], uuid->clock_seq_and_node[5], uuid->clock_seq_and_node[6],
           uuid->clock_seq_and_node[7]);
}

static int dev_uuid_test(void)
{
    int fd;
    ssize_t rc;
    uuid_t uuid;

    fd = tipc_connect(dev_name, uuid_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "uuid");
        return fd;
    }

    /* wait for test to complete */
    rc = read(fd, &uuid, sizeof(uuid));
    if (rc < 0) {
        perror("dev_uuid_test: read");
    } else if (rc != sizeof(uuid)) {
        fprintf(stderr, "unexpected uuid size (%d vs. %d)\n", (int)rc, (int)sizeof(uuid));
    } else {
        print_uuid(dev_name, &uuid);
    }

    tipc_close(fd);

    return 0;
}

static int ta_access_test(void)
{
    int fd;

    if (!opt_silent) {
        printf("%s:\n", __func__);
    }

    fd = tipc_connect(dev_name, ta_only_name);
    if (fd >= 0) {
        fprintf(stderr, "Succeed to connect to '%s' service\n", "ta_only");
        tipc_close(fd);
    }

    fd = tipc_connect(dev_name, ns_only_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "ns_only");
        return fd;
    }
    tipc_close(fd);

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int _writev_test_async(uint repeat, uint msgsz, bool var, int seed) {
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    const unsigned int min_msg_len = (sizeof(unsigned int) + sizeof(size_t));

    /* enforce lower bound for msg size to allow for order verification */
    if (msgsz < sizeof(unsigned int)) {
        msgsz = sizeof(unsigned int);
    }

    char tx0_buf[msgsz];
    char tx1_buf[msgsz];
    char rx_buf[msgsz];
    struct iovec tx_iovs[2] = {{tx0_buf, 0}, {tx1_buf, 0}};
    unsigned int* p0 = tx_iovs[0].iov_base;
    unsigned int* p1 = tx_iovs[1].iov_base;

    if (!opt_silent) {
        fprintf(stderr, "%s: repeat %u: msgsz %u: variable %s\n", __func__, repeat, msgsz,
                var ? "true" : "false");
    }

    const char* service_name = echo_name;
    if (srv_name) {
        service_name = srv_name;
    }

    echo_fd = tipc_connect(dev_name, service_name);
    if (echo_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, service_name);
        return echo_fd;
    }

    fprintf(stderr, "seed= %d connected to '%s', fd= %d\n", seed, service_name, echo_fd);

    /* make read/write not block */
    rc = fcntl(echo_fd, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "fcntl non-blocking mode failed (%d)\n", rc == -1 ? -errno : rc);
    }

    /* set up and run a loop that reads and/or writes based on poll results */
    int tx_cnt = repeat;
    int rx_cnt = tx_cnt;
    bool abort_test = false;
    unsigned int rx_this_loop, tx_this_loop;
    unsigned int ceiling_rx_this_loop, ceiling_tx_this_loop;
    float acc_rx_per_loop = 0.0f, acc_tx_per_loop = 0.0f;
    int rx_loop_cnt = 0, tx_loop_cnt = 0;
    while (!abort_test && (tx_cnt >= 0 || rx_cnt >= 0)) {
        rx_this_loop = tx_this_loop = 0;

        /* send messages until all buffers are full */
        while (tx_cnt >= 0) {
            /* calculate variable length if applicable */
            msg_len = msgsz;
            if (var && msgsz) {
                msg_len = rand() % msgsz;
            }
            tx_iovs[0].iov_len = msg_len / 3;
            tx_iovs[0].iov_len -=
                    tx_iovs[0].iov_len % sizeof(unsigned int);  // alignment for embedding counters
            if (tx_iovs[0].iov_len < min_msg_len) {
                tx_iovs[0].iov_len = min_msg_len;
            }
            tx_iovs[1].iov_len = msg_len - tx_iovs[0].iov_len;

            /* embed counter into message */
            p0[0] = tx_cnt + seed;
            p1[0] = tx_cnt + seed + repeat;

            /* embed lengths into message so that rx can verify */
            p0[1] = tx_iovs[0].iov_len;
            p1[1] = tx_iovs[1].iov_len;

            /* send */
            rc = writev(echo_fd, tx_iovs, 2);
            if (rc == -1 && errno == EAGAIN) {
                break;  // try again later
            } else if ((size_t)rc != msg_len) {
                fprintf(stderr, "write error (%d) msg_len (%zu)\n", rc == -1 ? -errno : rc,
                        msg_len);
                abort_test = true;
                break;
            }
            tx_cnt--;
            tx_this_loop++;
        }

        /* drain all messages */
        while (rx_cnt >= 0) {
            rc = read(echo_fd, rx_buf, sizeof(rx_buf));
            if (rc == -1 && errno == EAGAIN) {
                break;  // try again later
            }
            if (rc < 0) {
                fprintf(stderr, "read error (%d)\n", rc == -1 ? -errno : rc);
                abort_test = true;
                break;
            }

            /* verify minimum size to do verification steps below */
            if ((size_t)rc < min_msg_len) {
                fprintf(stderr, "data truncated (%zu vs. %zu)\n", rc, msg_len);
                abort_test = true;
                break;
            }

            unsigned int* p = (void*)rx_buf;

            /* verify first iov */
            unsigned int test_cnt = p[0];
            if ((rx_cnt + seed) != test_cnt) {
                fprintf(stderr, "data[0] mismatch expect= %d, have= %d\n", rx_cnt + seed, test_cnt);
                abort_test = true;
                break;
            }

            /* find length of first iov */
            size_t test_iov_len = p[1];  // FIXME: this only works for sizeof(size_t) == 4
            if (test_iov_len >= rc) {
                fprintf(stderr, "test_iov_len= %d out of range\n", test_iov_len);
                abort_test = true;
                break;
            }

            /* verify second iov */
            test_cnt = p[test_iov_len / sizeof(unsigned int)];
            if ((rx_cnt + seed + repeat) != test_cnt) {
                fprintf(stderr, "data[1] mismatch expect= %d, have= %d\n", rx_cnt + seed + repeat,
                        test_cnt);
                abort_test = true;
                break;
            }

            rx_cnt--;
            rx_this_loop++;
        }

        if (tx_this_loop > ceiling_tx_this_loop) {
            ceiling_tx_this_loop = tx_this_loop;
        }
        if (rx_this_loop > ceiling_rx_this_loop) {
            ceiling_rx_this_loop = rx_this_loop;
        }
        if (tx_this_loop > 0) {
            acc_tx_per_loop += tx_this_loop;
            ++tx_loop_cnt;
        }
        if (rx_this_loop > 0) {
            acc_rx_per_loop += rx_this_loop;
            ++rx_loop_cnt;
        }
    }

    tipc_close(echo_fd);

    printf("%d: ceiling tx= %d, rx= %d\n", seed, ceiling_tx_this_loop, ceiling_rx_this_loop);

    if (!opt_silent) {
        printf("%s: seed= %d done; avg per loop: tx= %.3f, rx= %.3f\n", __func__, seed,
               acc_tx_per_loop / tx_loop_cnt, acc_rx_per_loop / rx_loop_cnt);
    }

    return (rx_cnt <= 0 && tx_cnt <= 0) ? 0 : (rc == -1 ? -errno : -1);
}

static int _writev_test(uint repeat, uint msgsz, bool var, int seed) {
    uint i;
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    char tx0_buf[msgsz];
    char tx1_buf[msgsz];
    char rx_buf[msgsz];
    struct iovec iovs[2] = {{tx0_buf, 0}, {tx1_buf, 0}};
    (void)seed;

    if (!opt_silent) {
        printf("%s: repeat %u: msgsz %u: variable %s\n", __func__, repeat, msgsz,
               var ? "true" : "false");
    }

    echo_fd = tipc_connect(dev_name, echo_name);
    if (echo_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, echo_name);
        return echo_fd;
    }

    for (i = 0; i < repeat; i++) {
        msg_len = msgsz;
        if (opt_variable && msgsz) {
            msg_len = rand() % msgsz;
        }

        iovs[0].iov_len = msg_len / 3;
        iovs[1].iov_len = msg_len - iovs[0].iov_len;

        memset(tx0_buf, i + 1, iovs[0].iov_len);
        memset(tx1_buf, i + 2, iovs[1].iov_len);
        memset(rx_buf, i + 3, sizeof(rx_buf));

        rc = writev(echo_fd, iovs, 2);
        if (rc < 0) {
            perror("writev_test: writev");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "writev",
                    (size_t)rc, msg_len);
            break;
        }

        rc = read(echo_fd, rx_buf, sizeof(rx_buf));
        if (rc < 0) {
            perror("writev_test: read");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "read",
                    (size_t)rc, msg_len);
            break;
        }

        if (memcmp(tx0_buf, rx_buf, iovs[0].iov_len)) {
            fprintf(stderr, "%s: data mismatch: buf 0\n", __func__);
            break;
        }

        if (memcmp(tx1_buf, rx_buf + iovs[0].iov_len, iovs[1].iov_len)) {
            fprintf(stderr, "%s: data mismatch, buf 1\n", __func__);
            break;
        }
    }

    tipc_close(echo_fd);

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

void* writev_test_thread(void* arg) {
    threaded_test_args_t* et = (threaded_test_args_t*)arg;

    if (et->async) {
        et->result = _writev_test_async(et->repeat, et->msgsz, et->var, et->seed);
    } else {
        et->result = _writev_test(et->repeat, et->msgsz, et->var, et->seed);
    }

    return NULL;
}

static int readv_test(uint repeat, uint msgsz, bool var)
{
    uint i;
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    char tx_buf[msgsz];
    char rx0_buf[msgsz];
    char rx1_buf[msgsz];
    struct iovec iovs[2] = {{rx0_buf, 0}, {rx1_buf, 0}};

    if (!opt_silent) {
        printf("%s: repeat %u: msgsz %u: variable %s\n", __func__, repeat, msgsz,
               var ? "true" : "false");
    }

    echo_fd = tipc_connect(dev_name, echo_name);
    if (echo_fd < 0) {
        fprintf(stderr, "%s: Failed to connect to '%s' service\n", __func__, echo_name);
        return echo_fd;
    }

    for (i = 0; i < repeat; i++) {
        msg_len = msgsz;
        if (opt_variable && msgsz) {
            msg_len = rand() % msgsz;
        }

        iovs[0].iov_len = msg_len / 3;
        iovs[1].iov_len = msg_len - iovs[0].iov_len;

        memset(tx_buf, i + 1, sizeof(tx_buf));
        memset(rx0_buf, i + 2, iovs[0].iov_len);
        memset(rx1_buf, i + 3, iovs[1].iov_len);

        rc = write(echo_fd, tx_buf, msg_len);
        if (rc < 0) {
            perror("readv_test: write");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "write",
                    (size_t)rc, msg_len);
            break;
        }

        rc = readv(echo_fd, iovs, 2);
        if (rc < 0) {
            perror("readv_test: readv");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "write",
                    (size_t)rc, msg_len);
            break;
        }

        if (memcmp(rx0_buf, tx_buf, iovs[0].iov_len)) {
            fprintf(stderr, "%s: data mismatch: buf 0\n", __func__);
            break;
        }

        if (memcmp(rx1_buf, tx_buf + iovs[0].iov_len, iovs[1].iov_len)) {
            fprintf(stderr, "%s: data mismatch, buf 1\n", __func__);
            break;
        }
    }

    tipc_close(echo_fd);

    if (!opt_silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int send_fd_test(void) {
    int ret;
    int dma_buf = -1;
    int fd = -1;
    volatile char* buf = MAP_FAILED;
    BufferAllocator* allocator = NULL;

    const size_t num_pages = 10;

    fd = tipc_connect(dev_name, receiver_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to test support TA - is it missing?\n");
        ret = -1;
        goto cleanup;
    }

    allocator = CreateDmabufHeapBufferAllocator();
    if (!allocator) {
        fprintf(stderr, "Failed to create dma-buf allocator.\n");
        ret = -1;
        goto cleanup;
    }

    size_t buf_size = PAGE_SIZE * num_pages;
    dma_buf = DmabufHeapAlloc(allocator, "system", buf_size, 0, 0 /* legacy align */);
    if (dma_buf < 0) {
        ret = dma_buf;
        fprintf(stderr, "Failed to create dma-buf fd of size %zu err (%d)\n", buf_size, ret);
        goto cleanup;
    }

    buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "Failed to map dma-buf: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }

    strcpy((char*)buf, "From NS");

    struct trusty_shm shm = {
            .fd = dma_buf,
            .transfer = TRUSTY_SHARE,
    };

    ssize_t rc = tipc_send(fd, NULL, 0, &shm, 1);
    if (rc < 0) {
        fprintf(stderr, "tipc_send failed: %zd\n", rc);
        ret = rc;
        goto cleanup;
    }
    char c;
    read(fd, &c, 1);
    tipc_close(fd);

    ret = 0;
    for (size_t skip = 0; skip < num_pages; skip++) {
        ret |= strcmp("Hello from Trusty!", (const char*)&buf[skip * PAGE_SIZE]) ? (-1) : 0;
    }

cleanup:
    if (buf != MAP_FAILED) {
        munmap((char*)buf, PAGE_SIZE);
    }
    close(dma_buf);
    if (allocator) {
        FreeDmabufHeapBufferAllocator(allocator);
    }
    tipc_close(fd);
    return ret;
}

int main(int argc, char **argv)
{
    int rc = 0;

    if (argc <= 1) {
        print_usage_and_exit(argv[0], EXIT_FAILURE, false);
    }

    parse_options(argc, argv);

    if (!dev_name) {
        dev_name = TIPC_DEFAULT_DEVNAME;
    }

    if (!test_name) {
        fprintf(stderr, "need a Test to run\n");
        print_usage_and_exit(argv[0], EXIT_FAILURE, true);
    }

    if (strcmp(test_name, "connect") == 0) {
        rc = connect_test(opt_repeat);
    } else if (strcmp(test_name, "connect_foo") == 0) {
        rc = connect_foo(opt_repeat);
    } else if (strcmp(test_name, "burst_write") == 0) {
        rc = burst_write_test(opt_repeat, opt_msgburst, opt_msgsize, opt_variable);
    } else if (strcmp(test_name, "select") == 0) {
        rc = select_test(opt_repeat, opt_msgburst, opt_msgsize);
    } else if (strcmp(test_name, "blocked_read") == 0) {
        rc = blocked_read_test(opt_repeat);
    } else if (strcmp(test_name, "closer1") == 0) {
        rc = closer1_test(opt_repeat);
    } else if (strcmp(test_name, "closer2") == 0) {
        rc = closer2_test(opt_repeat);
    } else if (strcmp(test_name, "closer3") == 0) {
        rc = closer3_test(opt_repeat);
    } else if (strcmp(test_name, "echo_async") == 0) {
        rc = threaded_test(echo_test_thread, opt_thread_cnt, opt_repeat, opt_msgsize, opt_variable,
                           true);
    } else if (strcmp(test_name, "echo") == 0) {
        rc = threaded_test(echo_test_thread, opt_thread_cnt, opt_repeat, opt_msgsize, opt_variable,
                           false);
    } else if (strcmp(test_name, "ta2ta-ipc") == 0) {
        rc = ta2ta_ipc_test();
    } else if (strcmp(test_name, "dev-uuid") == 0) {
        rc = dev_uuid_test();
    } else if (strcmp(test_name, "ta-access") == 0) {
        rc = ta_access_test();
    } else if (strcmp(test_name, "writev_async") == 0) {
        rc = threaded_test(writev_test_thread, opt_thread_cnt, opt_repeat, opt_msgsize,
                           opt_variable, true);
    } else if (strcmp(test_name, "writev") == 0) {
        rc = threaded_test(writev_test_thread, opt_thread_cnt, opt_repeat, opt_msgsize,
                           opt_variable, false);
    } else if (strcmp(test_name, "readv") == 0) {
        rc = readv_test(opt_repeat, opt_msgsize, opt_variable);
    } else if (strcmp(test_name, "send-fd") == 0) {
        rc = send_fd_test();
    } else if (strcmp(test_name, "chan_interference") == 0) {
        rc = channel_interference_test(opt_repeat, opt_msgsize, opt_variable);
    } else {
        fprintf(stderr, "Unrecognized test name '%s'\n", test_name);
        print_usage_and_exit(argv[0], EXIT_FAILURE, true);
    }

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
