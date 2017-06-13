/* Copyright (C) 2017 The Android Open Source Project
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
/* srv1 starts at boot and restarts on exit*/
#define PERSISTENT_PORT  "com.android.trusty.appmgmt.srv1"
/* srv2 starts on port connection and does not retart on exit*/
#define ONESHOT_PORT "com.android.trusty.appmgmt.srv2"
#define START_PORT "com.android.trusty.appmgmt.srv2.start"
/* Period in msecs. Must be synced with the value in the app manager */
#define APP_RESTART_PERIOD 1000
/* Must be synced with the value in the app manager */
#define APP_SUCCESS_THRESHOLD 500
#define TIMEOUT_PER_RESTART (APP_RESTART_PERIOD * 5)
#define STRESS_TIMEOUT(count) (TIMEOUT_PER_RESTART * count)
#define DEFAULT_COUNT (5)
#define DEFAULT_PRINT_INTERVAL 10000
#define DEFAULT_PRINT_COUNT 100
#define CMD_EXIT 101
#define RESP_OK 1

static bool verbose = true;
static unsigned int count = DEFAULT_COUNT;

#define VERBOSE_ERROR(fmt, ...) \
    if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__)

#define WAIT_FOR_APP_RESTART()			\
    sleep(TIMEOUT_PER_RESTART / 1000)

#define WAIT_FOR_APP_SUCCESS()			\
    usleep(APP_SUCCESS_THRESHOLD * 1000)

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
"  -c, --count           number of restarts to use in stress test. if 0 the test runs indefinitely. Default 5.\n"
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
        tx_buff_[0] = CMD_EXIT;
    }

    virtual void TearDown() {
        if (fd_ >= 0)
            tipc_close(fd_);
    }

protected:
    int fd_;
    uint8_t rx_buff_[1];
    uint8_t tx_buff_[1];
};

TEST_F(AppMgrTest, AppBootStartNegative)
{
    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, ONESHOT_PORT);
    ASSERT_LT(fd_, 0) << "Unexpected connection to " << ONESHOT_PORT;
}

TEST_F(AppMgrTest, AppBootStartPositive)
{
    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, PERSISTENT_PORT);
    ASSERT_GE(fd_, 0) << "Could not connect to " << PERSISTENT_PORT;
    tipc_close(fd_);
}

TEST_F(AppMgrTest, AppPortStartNegative)
{
    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, ONESHOT_PORT);
    ASSERT_LT(fd_, 0) << "Unexpected connection to " << ONESHOT_PORT;

    WAIT_FOR_APP_RESTART();

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, ONESHOT_PORT);
    ASSERT_LT(fd_, 0) << "Unexpected connection to " << ONESHOT_PORT;
}

TEST_F(AppMgrTest, AppPortStartPositive)
{
    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, START_PORT);
    ASSERT_LT(fd_, 0) << "Unexpected connection to " << START_PORT;
    tipc_close(fd_);

    WAIT_FOR_APP_RESTART();

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, ONESHOT_PORT);
    ASSERT_GE(fd_, 0) << "Could not connect to " << ONESHOT_PORT;
    tipc_close(fd_);
}

TEST_F(AppMgrTest, AppRestartNegative)
{
    int  rc;

    /* Avoid potential race with a previous test where srv2 hasn't exited yet */
    WAIT_FOR_APP_RESTART();

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, START_PORT);
    ASSERT_LT(fd_, 0) << "Unexpected connection to " << START_PORT;
    tipc_close(fd_);

    WAIT_FOR_APP_RESTART();

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, ONESHOT_PORT);
    ASSERT_GE(fd_, 0) << "Could not connect to " << ONESHOT_PORT;

    rc = write(fd_, tx_buff_, sizeof(tx_buff_));
    ASSERT_EQ((size_t)rc, sizeof(tx_buff_)) << "Failed to send cmd";

    rc = read(fd_, rx_buff_, sizeof(rx_buff_));
    ASSERT_EQ((size_t)rc, sizeof(rx_buff_)) << "Failed to read rsp";
    ASSERT_EQ(rx_buff_[0], RESP_OK) << "Received incorrect rsp";

    tipc_close(fd_);

    WAIT_FOR_APP_RESTART();

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, ONESHOT_PORT);
    ASSERT_LT(fd_, 0) << "Unexpected connection to " << ONESHOT_PORT;
}

TEST_F(AppMgrTest, AppRestartPositive)
{
    int  rc;

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, PERSISTENT_PORT);
    ASSERT_GE(fd_, 0) << "Could not connect to " << PERSISTENT_PORT;

    rc = write(fd_, tx_buff_, sizeof(tx_buff_));
    ASSERT_EQ((size_t)rc, sizeof(tx_buff_)) << "Failed to send cmd";

    rc = read(fd_, rx_buff_, sizeof(rx_buff_));
    ASSERT_EQ((size_t)rc, sizeof(rx_buff_)) << "Failed to read rsp";
    ASSERT_EQ(rx_buff_[0], RESP_OK) << "Recevied incorrect rsp";

    tipc_close(fd_);

    WAIT_FOR_APP_RESTART();

    fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, PERSISTENT_PORT);
    ASSERT_GE(fd_, 0) << "Could not recconect to " << PERSISTENT_PORT;
}

TEST_F(AppMgrTest, AppRestartStress)
{
    int  rc;
    unsigned restarts = 0;
    unsigned success_time;
    bool forever;
    bool timed_out = false;
    int print_interval;

    if (count == 0) {
        forever = true;
        print_interval = DEFAULT_PRINT_INTERVAL;
        std::cout << "Runnig for infinite restarts" << std::endl;
    }
    else {
        forever = false;
        print_interval = count >= DEFAULT_PRINT_COUNT ?
	        count / DEFAULT_PRINT_COUNT : 1;
        std::cout << "Running for " << count << " restarts"  << std::endl;
    }

    success_time = gettime_msecs();

    while(forever || (restarts != count && !timed_out)) {
        fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, PERSISTENT_PORT);
        if (fd_ < 0) {
            VERBOSE_ERROR("failed to connect to test app: %s\n", strerror(-fd_));
            continue;
        }

        WAIT_FOR_APP_SUCCESS();

        rc = write(fd_, tx_buff_, sizeof(tx_buff_));
        if ((size_t)rc != sizeof(tx_buff_)) {
            VERBOSE_ERROR("Could not send command: errno=%d: %s\n", errno,
                    strerror(errno));
            goto retry;
        }

        rc = read(fd_, rx_buff_, sizeof(rx_buff_));
        if ((size_t)rc != sizeof(rx_buff_)) {
            VERBOSE_ERROR("failed to read response: errno=%d: %s\n", errno,
                    strerror(errno));
            goto retry;
        }

        if (rx_buff_[0] != RESP_OK) {
            VERBOSE_ERROR("received incorrect response:%d\n", rx_buff_[0]);
            goto retry;
        }

        rx_buff_[0] = 0;
        restarts++;
        if (restarts % print_interval == 0)
            std::cout << "Restarts: " << restarts << std::endl;
retry:
        tipc_close(fd_);
        timed_out = gettime_msecs() - success_time > STRESS_TIMEOUT(count);
    }

    ASSERT_EQ(restarts, count) << "Could not complete stress test: "
            << restarts << " out of " << count << std::endl;
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parse_options(argc, argv);
    return RUN_ALL_TESTS();
}
