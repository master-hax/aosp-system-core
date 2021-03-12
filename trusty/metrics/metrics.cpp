/*
 * Copyright (C) 2021 The Android Open Sourete Project
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

#define LOG_TAG "metrics"

#include <android-base/logging.h>
#include <trusty/metrics/metrics.h>
#include <trusty/metrics/tipc.h>
#include <trusty/tipc.h>

namespace android {
namespace trusty {
namespace metrics {

using android::base::ErrnoError;
using android::base::Error;

std::unique_ptr<TrustyMetrics> TrustyMetrics::CreateTrustyMetrics(std::string tipc_dev,
                                                                  CrashCb cb) {
    std::unique_ptr<TrustyMetrics> metrics(new TrustyMetrics(std::move(tipc_dev), std::move(cb)));
    auto ret = metrics->Open();
    if (!ret.ok()) {
        LOG(ERROR) << "failed to create TrustyMetrics: " << ret.error();
        return nullptr;
    }

    return metrics;
}

TrustyMetrics::TrustyMetrics(std::string tipc_dev, CrashCb cb)
    : tipc_dev_(std::move(tipc_dev)), metrics_fd_(-1), crash_cb_(std::move(cb)) {}

TrustyMetrics::~TrustyMetrics() {}

Result<void> TrustyMetrics::Open() {
    int fd = tipc_connect(tipc_dev_.c_str(), METRICS_PORT);
    if (fd < 0) {
        return ErrnoError() << "failed to connect to Trusty metrics TA: ";
    }

    metrics_fd_.reset(fd);
    return {};
}

Result<void> TrustyMetrics::HandleEvent() {
    uint8_t msg[METRICS_MAX_MSG_SIZE];

    auto rc = read(metrics_fd_, msg, sizeof(msg));
    if (rc < 0) {
        return ErrnoError() << "failed to read metrics message: ";
    }
    size_t msg_len = rc;

    if (msg_len < sizeof(metrics_hdr)) {
        return Error() << "message too small: " << rc;
    }
    auto req = reinterpret_cast<metrics_hdr*>(msg);
    size_t offset = sizeof(metrics_hdr);

    if (req->cmd != METRICS_CMD_REPORT_CRASH) {
        return Error() << "unknown command: " << req->cmd;
    }

    switch (req->cmd) {
        case METRICS_CMD_REPORT_CRASH: {
            if (msg_len < offset + sizeof(metrics_report_crash_req)) {
                return Error() << "message too small: " << rc;
            }
            auto crash_args = reinterpret_cast<metrics_report_crash_req*>(msg + offset);
            offset += sizeof(metrics_report_crash_req);

            if (msg_len < offset + crash_args->app_id_len) {
                return Error() << "message too small: " << rc;
            }
            auto app_id_ptr = reinterpret_cast<char*>(msg + offset);
            std::string app_id(app_id_ptr, crash_args->app_id_len);

            crash_cb_(crash_args->idx, std::move(app_id));
            break;
        }

        default:
            return Error() << "unknown event type: " << req->cmd;
    }

    metrics_hdr resp = {
            .cmd = METRICS_CMD_REPORT_CRASH | METRICS_CMD_RESP_BIT,
    };

    rc = write(metrics_fd_, &resp, sizeof(resp));
    if (rc < 0) {
        return ErrnoError() << "failed to request next metrics event: ";
    }

    if (rc != (int)sizeof(resp)) {
        return Error() << "unexpected number of bytes sent event: " << rc;
    }

    return {};
}

Result<void> TrustyMetrics::RunEventLoop() {
    while (true) {
        auto ret = HandleEvent();
        if (!ret.ok()) {
            return ret;
        }
    }
}

}  // namespace metrics
}  // namespace trusty
}  // namespace android
