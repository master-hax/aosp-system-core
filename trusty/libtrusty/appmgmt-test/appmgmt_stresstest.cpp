/* Copyright (C) 2018 The Android Open Source Project
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <getopt.h>
#include <gtest/gtest.h>
#include <trusty/tipc.h>
#include <iostream>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"
#define APP_RESTART_PERIOD 10
#define TIMEOUT_PER_RESTART (APP_RESTART_PERIOD * 5)
#define DEFAULT_COUNT 10000
#define DEFAULT_PRINT_INTERVAL 100

enum {
    CMD_NOP             = 0,
    CMD_CLOSE_PORT      = 1,
    CMD_EXIT            = 2,
    CMD_DELAYED_EXIT    = 3,
};

enum {
    RSP_OK              = 0,
    RSP_CMD_FAILED      = 1,
    RSP_INVALID_CMD     = 2,
};

static bool verbose = false;
static unsigned int count = DEFAULT_COUNT;

#define VERBOSE_ERROR(fmt, ...) \
    if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__)

#define WAIT_FOR_APP_RESTART()  \
    sleep(TIMEOUT_PER_RESTART / 1000)

static const char *_sopts = "hvc:";
static const struct option _lopts[] =  {
    {"help", no_argument, 0, 'h'},
    {"verbose", no_argument, 0, 'v'},
    {"count", required_argument, 0, 'c'},
    {0, 0, 0, 0}
};

static const char *usage =
"Usage: %s [options] \n"
"\n"
"options:\n"
"  -h, --help            prints this message and exit\n"
"  -v, --verbose         print more\n"
"  -c, --count           number of iterations run stress test for. Default 10000.\n"
"\n"
;

static const char *usage_long =
"\n"
;


static void print_usage_and_exit(const char *prog, int code)
{
    fprintf(stderr, usage, prog);
    VERBOSE_ERROR("%s", usage_long);
    exit(code);
}

static void parse_options(int argc, char **argv)
{
    int c;
    int oidx = 0;

    while (1)
    {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1)
            break; /* done */

        switch (c) {
        case 'v':
            verbose = true;
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'h':
            print_usage_and_exit(argv[0], EXIT_SUCCESS);
            break;
        default:
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static unsigned gettime_msecs()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

class AppMgrTest : public ::testing::Test {
public:

    AppMgrTest() {}
    virtual ~AppMgrTest() {}

    virtual void SetUp() {
        fd_ = -1;
        rx_buff_[0] = 0;
        tx_buff_[0] = 0;
    }

    virtual void TearDown() {
        if (fd_ >= 0)
            tipc_close(fd_);
    }

    void send_cmd(int cmd)
    {
        int rc;

        tx_buff_[0] = cmd;

        rc = write(fd_, tx_buff_, sizeof(tx_buff_));
        ASSERT_EQ((size_t)rc, sizeof(tx_buff_)) << "Failed to send cmd";

        rc = read(fd_, rx_buff_, sizeof(rx_buff_));
        ASSERT_EQ((size_t)rc, sizeof(rx_buff_)) << "Failed to read rsp";
        ASSERT_EQ(rx_buff_[0], RSP_OK) << "Recevied incorrect rsp" <<
                                            rx_buff_[0];
    }

    void try_connect(const char *port, bool expect_success)
    {
        fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, port);

        if (expect_success)
            ASSERT_GE(fd_, 0) << "Could not connect to " << port;
        else
            ASSERT_LT(fd_, 0) << "Unexpected connection to " << port;
    }

protected:
    int fd_;
    uint8_t rx_buff_[1];
    uint8_t tx_buff_[1];
};



/* srv1 starts at boot and restarts on exit and creates one regular port*/
#define PERSISTENT_PORT  "com.android.trusty.appmgmt.srv1"
/* srv2 does not start at boot and creates 2 ports: a start port and a
 * regular port */
#define CTRL_PORT "com.android.trusty.appmgmt.srv2"
#define START_PORT "com.android.trusty.appmgmt.srv2.start"

TEST_F(AppMgrTest, AppRestartStress)
{
    unsigned restarts = 0;
    unsigned start_time;
    unsigned print_count;
    bool timed_out = false;

    print_count = count / DEFAULT_PRINT_INTERVAL;

    std::cout << "Running for " << count << " restarts"  << std::endl;

    start_time = gettime_msecs();

    while(restarts != count && !timed_out) {
        fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, PERSISTENT_PORT);
        if (fd_ < 0) {
            VERBOSE_ERROR("failed to connect to test app: %s\n",
                          strerror(-fd_));
            continue;
        }

        send_cmd(CMD_EXIT);

        restarts++;
        if (restarts % print_count == 0)
            std::cout << "Restarts: " << restarts << std::endl;
        tipc_close(fd_);
        timed_out = gettime_msecs() - start_time > TIMEOUT_PER_RESTART * count;
    }

    ASSERT_EQ(restarts, count) << "Could not complete stress test: "
                               << restarts << " out of " << count << std::endl;
}

TEST_F(AppMgrTest, AppSartPortStress)
{
    unsigned starts = 0;
    unsigned print_count;

    print_count = count / DEFAULT_PRINT_INTERVAL;

    std::cout << "Running for " << count << " starts"  << std::endl;

    while(starts != count) {
        /* Start srv2 */
        try_connect(START_PORT, true);
        send_cmd(CMD_NOP);
        tipc_close(fd_);
        /* Check srv2 is running */
        try_connect(CTRL_PORT, true);
        /* Make srv2 close START_PORT  (~50% of the time) */
        if (rand() & 1)
            send_cmd(CMD_CLOSE_PORT);
        else
            send_cmd(CMD_NOP);
        tipc_close(fd_);
        /* Shutdown srv2 after a delay */
        try_connect(CTRL_PORT, true);
        send_cmd(CMD_DELAYED_EXIT);
        tipc_close(fd_);

        starts++;
        if (starts % print_count == 0)
            std::cout << "starts: " << starts << std::endl;
    }
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parse_options(argc, argv);
    return RUN_ALL_TESTS();
}
