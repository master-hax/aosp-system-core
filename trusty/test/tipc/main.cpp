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

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <trusty/test/common/utils.h>
#include <trusty/tipc.h>

#include <BufferAllocator/BufferAllocator.h>

using android::base::unique_fd;
using android::trusty::test::GetTrustyFlavor;
using android::trusty::test::TrustyFlavor;
using namespace std::chrono_literals;

static const char* trusty_dev = "/dev/trusty-ipc-dev0";

static const char* uuid_port = "com.android.ipc-unittest.srv.uuid";
static const char* echo_port = "com.android.ipc-unittest.srv.echo";
static const char* ta_only_port = "com.android.ipc-unittest.srv.ta_only";
static const char* ns_only_port = "com.android.ipc-unittest.srv.ns_only";
static const char* datasink_port = "com.android.ipc-unittest.srv.datasink";
static const char* closer1_port = "com.android.ipc-unittest.srv.closer1";
static const char* closer2_port = "com.android.ipc-unittest.srv.closer2";
static const char* closer3_port = "com.android.ipc-unittest.srv.closer3";
static const char* receiver_port = "com.android.trusty.memref.receiver";

#define MSG_LEN (32)
#define MSG_BURST (32)

class TipcTest : public ::testing::Test {
  public:
    virtual void SetUp() override {
        auto trusty_flavor = android::trusty::test::GetTrustyFlavor();
        if (trusty_flavor != TrustyFlavor::Test) {
            GTEST_SKIP() << "Must be a test build of Trusty";
        }
    }
};

TEST_F(TipcTest, Connect) {
    unique_fd echo_fd(tipc_connect(trusty_dev, echo_port));
    ASSERT_GE(echo_fd, 0) << "Failed to connect to 'echo' service";

    unique_fd datasink_fd(tipc_connect(trusty_dev, datasink_port));
    ASSERT_GE(datasink_fd, 0) << "Failed to connect to 'datasink' service";
}

TEST_F(TipcTest, ConnectFoo) {
    unique_fd fd(tipc_connect(trusty_dev, "foo"));
    ASSERT_LT(fd, 0) << "Succeeded connecting to a non-existent 'foo' service";
}

TEST_F(TipcTest, Closer1) {
    GTEST_SKIP() << "TODO: Closer1 service is flaky. Enable after fixing";
    unique_fd fd(tipc_connect(trusty_dev, closer1_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'closer1' service";
}

TEST_F(TipcTest, Closer2) {
    unique_fd fd(tipc_connect(trusty_dev, closer2_port));
    ASSERT_LT(fd, 0) << "Connecting to 'closer2' should always fail";
}

TEST_F(TipcTest, Closer3) {
    static const size_t num_fds = 4;
    unique_fd fd[num_fds];
    char buf[MSG_LEN];

    for (int i = 0; i < num_fds; i++) {
        fd[i].reset(tipc_connect(trusty_dev, closer3_port));
        ASSERT_GE(fd[i], 0) << "Failed to connect to 'closer3' service";

        memset(buf, i, sizeof(buf));
        int rc = write(fd[i], buf, sizeof(buf));
        ASSERT_EQ(rc, sizeof(buf));
    }

    /* sleep a bit */
    sleep(1);

    for (int i = 0; i < num_fds; i++) {
        /* Connection should be closed by remote by this point */
        int rc = write(fd[i], buf, sizeof(buf));
        ASSERT_LT(rc, 0);
    }
}

TEST_F(TipcTest, Echo) {
    unique_fd fd(tipc_connect(trusty_dev, echo_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'echo' service";

    uint8_t tx_buf[MSG_LEN];
    memset(tx_buf, 1, sizeof(tx_buf));

    int rc = write(fd, tx_buf, sizeof(tx_buf));
    ASSERT_EQ(rc, sizeof(tx_buf));

    uint8_t rx_buf[MSG_LEN];
    memset(rx_buf, 0, sizeof(rx_buf));

    rc = read(fd, rx_buf, sizeof(rx_buf));
    ASSERT_EQ(rc, sizeof(rx_buf));

    rc = memcmp(tx_buf, rx_buf, sizeof(tx_buf));
    ASSERT_EQ(rc, 0);
}

TEST_F(TipcTest, BurstWrite) {
    unique_fd fd(tipc_connect(trusty_dev, datasink_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'datasink' service";

    uint8_t tx_buf[MSG_LEN];
    memset(tx_buf, 1, sizeof(tx_buf));

    for (int i = 0; i < MSG_BURST; i++) {
        int rc = write(fd, tx_buf, sizeof(tx_buf));
        ASSERT_EQ(rc, sizeof(tx_buf));
    }
}

TEST_F(TipcTest, Select) {
    unique_fd fd(tipc_connect(trusty_dev, echo_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'echo' service";

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    struct timeval tv = {
            .tv_sec = 1,
            .tv_usec = 0,
    };

    int rc = select(1, &rfds, NULL, NULL, &tv);
    ASSERT_EQ(rc, 0) << "select() did not time out";

    uint8_t tx_buf[MSG_LEN];
    memset(tx_buf, 1, sizeof(tx_buf));

    for (int i = 0; i < MSG_BURST; i++) {
        int rc = write(fd, tx_buf, sizeof(tx_buf));
        ASSERT_EQ(rc, sizeof(tx_buf));
    }
}

TEST_F(TipcTest, BlockedRead) {
    uint8_t rx_buf[MSG_LEN];

    unique_fd fd(tipc_connect(trusty_dev, echo_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'echo' service";

    ASSERT_DEATH(
            {
                alarm(3 /* seconds */);
                read(fd, rx_buf, sizeof(rx_buf));
                alarm(0);
            },
            "");
}

struct uuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_and_node[8];
};

TEST_F(TipcTest, UUID) {
    unique_fd fd(tipc_connect(trusty_dev, uuid_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'uuid' service";

    struct uuid uuid;
    memset(&uuid, 1, sizeof(uuid));

    int rc = read(fd, &uuid, sizeof(uuid));
    ASSERT_EQ(rc, sizeof(uuid));
}

TEST_F(TipcTest, TaAccess) {
    unique_fd ta_only_fd(tipc_connect(trusty_dev, ta_only_port));
    ASSERT_LT(ta_only_fd, 0) << "Connected to 'ta_only' service";

    unique_fd ns_only_fd(tipc_connect(trusty_dev, ns_only_port));
    ASSERT_GE(ns_only_fd, 0) << "Failed to connect to 'ns_only' service";
}

TEST_F(TipcTest, Writev) {
    unique_fd fd(tipc_connect(trusty_dev, echo_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'echo' service";

    uint8_t tx0_buf[MSG_LEN];
    uint8_t tx1_buf[MSG_LEN];
    iovec iovs[2] = {
            {
                    .iov_base = tx0_buf,
                    .iov_len = MSG_LEN / 3,
            },
            {
                    .iov_base = tx1_buf,
                    .iov_len = MSG_LEN - iovs[0].iov_len,
            },
    };

    memset(tx0_buf, 1, sizeof(tx0_buf));
    memset(tx1_buf, 2, sizeof(tx1_buf));

    int rc = writev(fd, iovs, 2);
    ASSERT_EQ(rc, MSG_LEN);

    uint8_t rx_buf[MSG_LEN];
    memset(rx_buf, 3, sizeof(rx_buf));

    rc = read(fd, rx_buf, sizeof(rx_buf));
    ASSERT_EQ(rc, sizeof(rx_buf));

    rc = memcmp(tx0_buf, rx_buf, iovs[0].iov_len);
    ASSERT_EQ(rc, 0) << "Data mismatch";

    rc = memcmp(tx1_buf, rx_buf + iovs[0].iov_len, iovs[1].iov_len);
    ASSERT_EQ(rc, 0) << "Data mismatch";
}

TEST_F(TipcTest, Readv) {
    unique_fd fd(tipc_connect(trusty_dev, echo_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'echo' service";

    uint8_t tx_buf[MSG_LEN];
    memset(tx_buf, 1, sizeof(tx_buf));

    int rc = write(fd, tx_buf, sizeof(tx_buf));
    ASSERT_EQ(rc, sizeof(tx_buf));

    uint8_t rx0_buf[MSG_LEN];
    uint8_t rx1_buf[MSG_LEN];
    iovec iovs[2] = {
            {
                    .iov_base = rx0_buf,
                    .iov_len = MSG_LEN / 3,
            },
            {
                    .iov_base = rx1_buf,
                    .iov_len = MSG_LEN - iovs[0].iov_len,
            },
    };
    memset(rx0_buf, 0, sizeof(rx0_buf));
    memset(rx1_buf, 0, sizeof(rx1_buf));

    readv(fd, iovs, 2);
    ASSERT_EQ(rc, sizeof(tx_buf));

    rc = memcmp(rx0_buf, tx_buf, iovs[0].iov_len);
    ASSERT_EQ(rc, 0) << "Data mismatch";

    rc = memcmp(rx1_buf, tx_buf + iovs[0].iov_len, iovs[1].iov_len);
    ASSERT_EQ(rc, 0) << "Data mismatch";
}

TEST_F(TipcTest, SendFd) {
    unique_fd fd(tipc_connect(trusty_dev, receiver_port));
    ASSERT_GE(fd, 0) << "Failed to connect to 'receiver' service";

    const size_t num_pages = 10;
    size_t buf_len = PAGE_SIZE * num_pages;

    BufferAllocator allocator;
    unique_fd dma_buf(allocator.Alloc("system", buf_len));
    ASSERT_GE(dma_buf, 0) << "Failed to allocate a dma_buf";

    auto* buf = (volatile uint8_t*)mmap(0, buf_len, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    ASSERT_NE(buf, MAP_FAILED);

    strcpy((char*)buf, "From NS");

    trusty_shm shm = {
            .fd = dma_buf,
            .transfer = TRUSTY_SHARE,
    };
    int rc = tipc_send(fd, NULL, 0, &shm, 1);
    ASSERT_EQ(rc, 0) << "tipc_send() failed: " << rc;

    char c;
    read(fd, &c, 1);

    for (size_t skip = 0; skip < num_pages; skip++) {
        rc = strcmp("Hello from Trusty!", (const char*)&buf[skip * PAGE_SIZE]);
        ASSERT_EQ(rc, 0);
    }
}
