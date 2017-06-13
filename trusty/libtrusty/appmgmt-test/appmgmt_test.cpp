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

#include <gtest/gtest.h>
#include <trusty/tipc.h>
#include <iostream>

using namespace std;

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"
#define PERSISTENT_PORT  "com.android.trusty.appmgmt.srv1"
#define ONESHOT_PORT "com.android.trusty.appmgmt.srv2"
/* Period in msecs. Must be synced with the app manager */
#define APP_RESTART_PERIOD 1000
#define TIMEOUT_PER_RESTART (APP_RESTART_PERIOD * 5)
#define DEFAULT_COUNT 10 //(1000 * 1000)
#define DEFAULT_PRINT_INTERVAL 10000
#define DEFAULT_PRINT_COUNT 100
#define CMD_EXIT 101
#define RESP_OK 1

static bool verbose = 0;

#define VERBOSE_ERROR(fmt, ...) \
    if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__)

#define WAIT_FOR_APP_RESTART()			\
    sleep(TIMEOUT_PER_RESTART / 1000);

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

TEST_F(AppMgrTest, AppRestartNegative)
{
    int  rc;

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
    unsigned start_time;
    unsigned timeout;
    bool forever;
    bool timed_out = false;
    int print_interval;
    unsigned count = DEFAULT_COUNT;

    if (count == 0) {
        forever = true;
        print_interval = DEFAULT_PRINT_INTERVAL;
        cout << "Runnig for infinite restarts" << endl;
    }
    else {
        forever = false;
        print_interval = count >= DEFAULT_PRINT_COUNT ?
	        count / DEFAULT_PRINT_COUNT : 1;
        timeout = count * TIMEOUT_PER_RESTART;
        cout << "Running for " << count << " restarts"  << endl;
    }

    start_time = gettime_msecs();

    while(forever || (restarts != count && !timed_out)) {
        fd_ = tipc_connect(TIPC_DEFAULT_DEVNAME, PERSISTENT_PORT);
        if (fd_ < 0) {
            VERBOSE_ERROR("failed to connect to test app: %s\n", strerror(-fd_));
            continue;
        }

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
            cout << "Restarts: " << restarts << endl;
retry:
        tipc_close(fd_);
        timed_out = gettime_msecs() - start_time > timeout;
    }

    ASSERT_EQ(restarts, count) << "Could not complete stress test";
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
