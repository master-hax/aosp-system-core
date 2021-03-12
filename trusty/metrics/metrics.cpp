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

Result<void> TrustyMetrics::RequestNextEvent() {
    metrics_req req = {
            .cmd = METRICS_CMD_NEXT_EVENT,
    };

    auto rc = write(metrics_fd_, &req, sizeof(req));
    if (rc < 0) {
        return ErrnoError() << "failed to request next metrics event: ";
    }

    return {};
}

Result<void> TrustyMetrics::HandleEvent() {
    uint8_t msg[METRICS_MAX_MSG_SIZE];

    auto rc = read(metrics_fd_, msg, sizeof(msg));
    if (rc < 0) {
        return ErrnoError() << "failed to read metrics message: ";
    }

    if (rc < sizeof(metrics_resp)) {
        return Error() << "message too small: " << rc;
    }

    auto hdr = reinterpret_cast<metrics_resp*>(msg);
    if (hdr->cmd != (METRICS_CMD_NEXT_EVENT | METRICS_CMD_RESP_BIT)) {
        return Error() << "unknown command: " << hdr->cmd;
    }

    switch (hdr->type) {
        case METRICS_EVENT_TYPE_CRASH: {
            if (rc < sizeof(*hdr) + sizeof(metrics_crash_event_resp)) {
                return Error() << "message too small: " << rc;
            }
            auto args = reinterpret_cast<metrics_crash_event_resp*>(msg + sizeof(*hdr));

            if (rc < sizeof(*hdr) + sizeof(*args) + args->app_id_len) {
                return Error() << "message too small: " << rc;
            }
            auto app_id_ptr = reinterpret_cast<char*>(msg + sizeof(*hdr) + sizeof(*args));
            std::string app_id(app_id_ptr, args->app_id_len);

            crash_cb_(hdr->idx, std::move(app_id));
            return {};
        }

        default:
            return Error() << "unknown command: " << hdr->cmd;
    }
}

Result<void> TrustyMetrics::RunEventLoop() {
    while (true) {
        auto ret = RequestNextEvent();
        if (!ret.ok()) {
            return ret;
        }

        ret = HandleEvent();
        if (!ret.ok()) {
            return ret;
        }
    }
}

}  // namespace metrics
}  // namespace trusty
}  // namespace android
