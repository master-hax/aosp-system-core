/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <BufferAllocator/BufferAllocator.h>

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <sys/mman.h>
#include <trusty/tipc.h>

#include "tipc.h"

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define FFA_TEST_SRV_PORT "com.android.trusty.ffa.test.srv"

namespace android {
namespace trusty {

using android::base::unique_fd;

class TrustyFFATest : public ::testing::Test {
  public:
    virtual void SetUp() override {
        srv_.reset(tipc_connect(TIPC_DEV, FFA_TEST_SRV_PORT));
        ASSERT_GE(srv_, 0);

        buf_size_ = 10 * PAGE_SIZE;

        BufferAllocator allocator;
        dma_buf_.reset(allocator.Alloc("trusty", buf_size_));
        ASSERT_GE(dma_buf_, 0) << "Failed to allocate dma_buf";

        buf_ = mmap(0, buf_size_, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf_, 0);
        ASSERT_NE(buf_, MAP_FAILED) << "Failed to mmap() dma_buf";
    }

    void FFATestSrvSendBuf(uint32_t cmd, int dma_buf, uint32_t dma_buf_size, uint32_t arg) {
        ffa_test_srv_req req = {
                .cmd = cmd,
                .size = dma_buf_size,
                .arg = arg,
        };

        iovec iov = {
                .iov_base = &req,
                .iov_len = sizeof(req),
        };
        trusty_shm shm = {
                .fd = dma_buf,
                .transfer = TRUSTY_SHARE,
        };

        int rc = tipc_send(srv_, &iov, 1, &shm, 1);
        ASSERT_EQ(rc, sizeof(req));

        ffa_test_srv_resp resp;
        rc = read(srv_, &resp, sizeof(resp));
        ASSERT_EQ(rc, sizeof(resp));
        ASSERT_EQ(resp.cmd, cmd);
    }

    unique_fd srv_;
    unique_fd dma_buf_;
    void* buf_;
    size_t buf_size_;
};

TEST_F(TrustyFFATest, ShareOneBuf) {
    uint32_t arg = 0xdeadbeef;
    FFATestSrvSendBuf(FFA_TEST_SRV_CMD_MAP_WRITE_UNMAP, dma_buf_, buf_size_, arg);
    ASSERT_EQ(memcmp(buf_, &arg, sizeof(arg)), 0);
}

TEST_F(TrustyFFATest, MultMapUnmap) {
    for (int i = 0; i < MAX_MAPPED_BUFS; i++) {
        uint32_t arg = i;
        FFATestSrvSendBuf(FFA_TEST_SRV_CMD_MAP_WRITE_UNMAP, dma_buf_, buf_size_, arg);
        ASSERT_EQ(memcmp(buf_, &arg, sizeof(arg)), 0);
    }
}

TEST_F(TrustyFFATest, MultMapMultUnmap) {
    for (int i = 0; i < MAX_MAPPED_BUFS; i++) {
        uint32_t arg = i;
        FFATestSrvSendBuf(FFA_TEST_SRV_CMD_MAP_WRITE, dma_buf_, buf_size_, arg);
        ASSERT_EQ(memcmp(buf_, &arg, sizeof(arg)), 0);
    }
}

}  // namespace trusty
}  // namespace android
