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
#include <getopt.h>
#include <gtest/gtest.h>
#include <trusty/tipc.h>
#include <iostream>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"
#define APP_RESTART_PERIOD 10
#define TIMEOUT_PER_RESTART (APP_RESTART_PERIOD * 5)

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

#define VERBOSE_ERROR(fmt, ...) \
    if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__)

#define WAIT_FOR_APP_RESTART()  \
    sleep(TIMEOUT_PER_RESTART / 1000)

static const char *_sopts = "hvc:";
static const struct option _lopts[] =  {
    {"help", no_argument, 0, 'h'},
    {"verbose", no_argument, 0, 'v'},
    {0, 0, 0, 0}
};

static const char *usage =
"Usage: %s [options] \n"
"\n"
"options:\n"
"  -h, --help            prints this message and exit\n"
"  -v, --verbose         print more\n"
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
        case 'h':
            print_usage_and_exit(argv[0], EXIT_SUCCESS);
            break;
        default:
            print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
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


TEST_F(AppMgrTest, AppBootStartNegative)
{
    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);
}

TEST_F(AppMgrTest, AppBootStartPositive)
{
    /* Check srv1 is running */
    try_connect(PERSISTENT_PORT, true);
    /* Shutdown srv1 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);
}

TEST_F(AppMgrTest, AppPortStartNegative)
{
    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);

    WAIT_FOR_APP_RESTART();

    /* Check srv2 is still not running */
    try_connect(CTRL_PORT, false);
}

TEST_F(AppMgrTest, AppPortStartPositive)
{
    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);
    /* Start srv2 */
    try_connect(START_PORT, true);
    send_cmd(CMD_NOP);
    tipc_close(fd_);
    /* Check srv2 is running */
    try_connect(CTRL_PORT, true);
    /* Shutdown srv2 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);
}

TEST_F(AppMgrTest, AppPortStartPositiveOpenPort)
{
    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);
    /* Start srv2 */
    try_connect(START_PORT, true);
    send_cmd(CMD_NOP);
    tipc_close(fd_);
    /* Check srv2 is running */
    try_connect(CTRL_PORT, true);
    /* Shutdown srv2 after a delay */
    send_cmd(CMD_DELAYED_EXIT);
    tipc_close(fd_);
    /* Start srv2. This connection should arrive while the app is still running
     * from the previous start and has an open port but not accepting
     * connections
     */
    try_connect(START_PORT, true);
    send_cmd(CMD_NOP);
    tipc_close(fd_);
    /* Check srv2 is running */
    try_connect(CTRL_PORT, true);
    /* Shutdown srv2 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);
}

TEST_F(AppMgrTest, AppPortStartPositiveClosedPort)
{
    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);
    /* Start srv2 */
    try_connect(START_PORT, true);
    send_cmd(CMD_NOP);
    tipc_close(fd_);
    /* Check srv2 is running */
    try_connect(CTRL_PORT, true);
    /* Make srv2 close START_PORT */
    send_cmd(CMD_CLOSE_PORT);
    tipc_close(fd_);
    /* Shutdown srv2 after a delay */
    try_connect(CTRL_PORT, true);
    send_cmd(CMD_DELAYED_EXIT);
    tipc_close(fd_);
    /* Start srv2. This connection should arrive while the app is still running
     * from the previous start and has already closed its start port
     */
    try_connect(START_PORT, true);
    send_cmd(CMD_NOP);
    tipc_close(fd_);
    /* Check srv2 is running */
    try_connect(CTRL_PORT, true);
    /* Shutdown srv2 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);

}

TEST_F(AppMgrTest, AppRestartNegative)
{
    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);

    /* Start srv2 */
    try_connect(START_PORT, true);
    send_cmd(CMD_NOP);
    tipc_close(fd_);

    /* Check srv2 is running */
    try_connect(CTRL_PORT, true);
    /* Shutdown srv2 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);

    WAIT_FOR_APP_RESTART();

    /* Check srv2 is not running */
    try_connect(CTRL_PORT, false);
}

TEST_F(AppMgrTest, AppRestartPositive)
{
    /* Check srv1 is running */
    try_connect(PERSISTENT_PORT, true);
    /* Shutdown srv1 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);

    WAIT_FOR_APP_RESTART();

    /* Check srv1 is running */
    try_connect(PERSISTENT_PORT, true);
    /* Shutdown srv1 */
    send_cmd(CMD_EXIT);
    tipc_close(fd_);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    parse_options(argc, argv);
    return RUN_ALL_TESTS();
}
