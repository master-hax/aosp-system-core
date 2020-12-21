/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <android-base/logging.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <trusty/tipc.h>
#include <unistd.h>

#include <cutils/android_filesystem_config.h>

#include "DPUHandler.h"

constexpr const char kConfirmationuiDPUAppName[] = "com.android.trusty.secure_dpu";
static const char* kTrustyDeviceName = nullptr;

static const char* _sopts = "hp:d:";
static const struct option _lopts[] = {{"help", no_argument, NULL, 'h'},
                                       {"trusty_dev", required_argument, NULL, 'd'},
                                       {0, 0, 0, 0}};

static constexpr const int kInvalidHandle = -1;
static int SecureDPUHandle_ = kInvalidHandle;

static void show_usage_and_exit(int code) {
    LOG(ERROR) << "usage: securedpud -d <trusty_dev>";
    exit(code);
}

static void parse_args(int argc, char* argv[]) {
    int opt;
    int oidx = 0;

    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1) {
        switch (opt) {
            case 'd':
                kTrustyDeviceName = strdup(optarg);
                break;

            default:
                LOG(ERROR) << "unrecognized option: " << opt;
                show_usage_and_exit(EXIT_FAILURE);
        }
    }

    if (kTrustyDeviceName == nullptr) {
        LOG(ERROR) << "missing required argument(s)";
        show_usage_and_exit(EXIT_FAILURE);
    }

    LOG(INFO) << "starting securedpud";
    LOG(INFO) << "trusty dev: " << kTrustyDeviceName;
}

int main(int argc, char* argv[])
{
    uint8_t buf[android::trusty::secure_dpu::DPUHandler::maxBufferSize];

    /* parse arguments */
    parse_args(argc, argv);

    SecureDPUHandle_ = tipc_connect(kTrustyDeviceName,
                                    kConfirmationuiDPUAppName);
    if (SecureDPUHandle_ < 0) {
        return EXIT_FAILURE;
    }

    auto dpu_handler = std::make_shared<android::trusty::secure_dpu::DPUHandler>(
        [&](uint8_t buf[], size_t size) -> int {
            iovec iov[] = {
                {
                    .iov_base = buf,
                    .iov_len = size,
                },
            };
            auto rc = writev(SecureDPUHandle_, iov, 1);
            return rc < 0 ? 1 : 0;
        });
    if (!dpu_handler) {
        tipc_close(SecureDPUHandle_);
        return EXIT_FAILURE;
    }

    /* main loop */
    while (1) {
        iovec iov[] = {
            {
                .iov_base = buf,
                .iov_len = sizeof(buf),
            },
        };
        auto read_len = readv(SecureDPUHandle_, iov, 1);
        if (read_len > 0) {
            auto result = dpu_handler->handle(buf, read_len);
            if (!result.ok()) {
                LOG(ERROR) << result.error();
            }
        } else {
            LOG(ERROR) << "Failed to get message to TrustyApp";
        }
    }
    LOG(ERROR) << "exiting securedpud loop";

    if (SecureDPUHandle_ != kInvalidHandle) {
        tipc_close(SecureDPUHandle_);
    }
    return EXIT_FAILURE;
}
