/*
 * Copyright (C) 2020 The Android Open Sourete Project
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

#define LOG_TAG "spi_proxy"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <sys/mman.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/tipc.h>
#include <trusty/tipc.h>

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define COVERAGE_CLIENT_PORT "com.android.trusty.coverage.client"

#define countof(arr) (sizeof(arr) / sizeof(arr[0]))

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

namespace android {
namespace trusty {

CoverageRecord::CoverageRecord(struct uuid* uuid, size_t shm_len)
    : uuid_(*uuid), shm_(NULL), shm_len_(shm_len), coverage_srv_fd_(-1) {}

CoverageRecord::~CoverageRecord() {
    if (shm_) {
        munmap((void*)shm_, shm_len_);
    }
}

Result<void> CoverageRecord::RegisterShm(unique_fd memfd) {
    coverage_client_hdr hdr{
            .cmd = COVERAGE_CLIENT_CMD_OPEN,
    };
    coverage_client_open_args args{
            .uuid = uuid_,
            .shm_len = static_cast<uint32_t>(shm_len_),
    };

    iovec iov[] = {
            {
                    .iov_base = &hdr,
                    .iov_len = sizeof(hdr),
            },
            {
                    .iov_base = &args,
                    .iov_len = sizeof(args),
            },
    };

    struct trusty_shm shm {
        .fd = memfd, .transfer = TRUSTY_SHARE,
    };

    ssize_t rc = tipc_send(coverage_srv_fd_, iov, countof(iov), &shm, 1);
    if (rc < 0) {
        return ErrnoError() << "failed tipc_send(): ";
    }

    rc = read(coverage_srv_fd_, &hdr, sizeof(hdr));
    if (rc < 0) {
        return ErrnoError() << "failed get response: ";
    }

    if (hdr.cmd != (COVERAGE_CLIENT_CMD_OPEN | COVERAGE_CLIENT_CMD_RESP_BIT)) {
        return ErrnoError() << "unknown response cmd: " << hdr.cmd;
    }

    return {};
}

Result<void> CoverageRecord::Open() {
    if (shm_) {
        return {}; /* already initialized */
    }

    int fd = tipc_connect(TIPC_DEV, COVERAGE_CLIENT_PORT);
    if (fd < 0) {
        return ErrnoError() << "failed to connect to Trusty coverarge server: ";
    }
    coverage_srv_fd_.reset(fd);

    shm_len_ = (shm_len_ % PAGE_SIZE) ? (shm_len_ / PAGE_SIZE + 1) * PAGE_SIZE : shm_len_;

    fd = memfd_create("trusty-coverage", 0);
    if (fd < 0) {
        return ErrnoError() << "failed to create memfd: ";
    }
    unique_fd memfd(fd);

    if (ftruncate(memfd, shm_len_) < 0) {
        return ErrnoError() << "failed to resize memfd: ";
    }

    void* shm = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (shm == MAP_FAILED) {
        return ErrnoError() << "failed to map memfd: ";
    }

    auto ret = RegisterShm(std::move(memfd));
    if (!ret.ok()) {
        return Error() << "failed to send shared memory: ";
    }

    shm_ = shm;
    return {};
}

Result<void> CoverageRecord::RemoteOp(uint32_t cmd) {
    if (!shm_) {
        return Error() << "coverage record is not open: ";
    }

    coverage_client_hdr hdr{
            .cmd = cmd,
    };

    int rc = write(coverage_srv_fd_, &hdr, sizeof(hdr));
    if (rc != (int)sizeof(hdr)) {
        return ErrnoError() << "failed to send request to coverage server: ";
    }

    rc = read(coverage_srv_fd_, &hdr, sizeof(hdr));
    if (rc != (int)sizeof(hdr)) {
        return ErrnoError() << "failed to read reply from coverage server: ";
    }

    if (hdr.cmd != (cmd | COVERAGE_CLIENT_CMD_RESP_BIT)) {
        return ErrnoError() << "unknown response cmd: " << hdr.cmd;
    }

    return {};
}

Result<void> CoverageRecord::Pull() {
    return RemoteOp(COVERAGE_CLIENT_CMD_PULL);
}

Result<void> CoverageRecord::Reset() {
    return RemoteOp(COVERAGE_CLIENT_CMD_RESET);
}

Result<void> CoverageRecord::GetRawData(volatile void** begin, volatile void** end) {
    if (!shm_) {
        return Error() << "coverage record is not open: ";
    }

    *begin = shm_;
    *end = (uint8_t*)(*begin) + shm_len_;

    return {};
}

Result<uint64_t> CoverageRecord::CountBlocks() {
    assert(shm_);

    uint64_t counter = 0;

    volatile uint8_t* begin = NULL;
    volatile uint8_t* end = NULL;

    auto ret = GetRawData((volatile void**)&begin, (volatile void**)&end);
    if (!ret.ok()) {
        return Error() << "failed to get raw data: " << ret.error();
    }

    for (volatile uint8_t* x = begin; x < (uint8_t*)end; x++) {
        counter += *x;
    }

    return counter;
}

}  // namespace trusty
}  // namespace android
