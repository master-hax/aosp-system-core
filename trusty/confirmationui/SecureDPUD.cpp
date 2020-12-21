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
#include <unistd.h>

#include <cutils/android_filesystem_config.h>

#include "DPUHandler.h"
#include "TrustyApp.h"

constexpr const char kConfirmationuiDPUAppName[] = "com.android.trusty.secure_dpu";
static const char* kTrustyDeviceName = nullptr;

static const char* _sopts = "hp:d:";
static const struct option _lopts[] = {{"help", no_argument, NULL, 'h'},
                                       {"trusty_dev", required_argument, NULL, 'd'},
                                       {0, 0, 0, 0}};

static void show_usage_and_exit(int code) {
    LOG(ERROR) << "usage: securedpud -d <trusty_dev>";
    exit(code);
}

static int drop_privs(void) {
    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        return -1;
    }

    /*
     * ensure we're running as the system user
     */
    if (setgid(AID_SYSTEM) != 0) {
        return -1;
    }

    if (setuid(AID_SYSTEM) != 0) {
        return -1;
    }

    /*
     * drop all capabilities except SYS_RAWIO
     */
    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));
    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;

    capdata[CAP_TO_INDEX(CAP_SYS_RAWIO)].permitted = CAP_TO_MASK(CAP_SYS_RAWIO);
    capdata[CAP_TO_INDEX(CAP_SYS_RAWIO)].effective = CAP_TO_MASK(CAP_SYS_RAWIO);

    if (capset(&capheader, &capdata[0]) < 0) {
        return -1;
    }

    /* no-execute for user, no access for group and other */
    umask(S_IXUSR | S_IRWXG | S_IRWXO);

    return 0;
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
    uint8_t buf[android::dpu_handler::DPUHandler::maxBufferSize];

    /* drop privileges */
    if (drop_privs() < 0) return EXIT_FAILURE;

    /* parse arguments */
    parse_args(argc, argv);

    auto dpu_app = std::make_shared<android::trusty::TrustyApp>(kTrustyDeviceName, kConfirmationuiDPUAppName);
    if (!dpu_app) return EXIT_FAILURE;  // TeeuiRc::SystemError

    auto dpu_handler = std::make_shared<android::dpu_handler::DPUHandler>(
        [&](uint8_t buf[], size_t size) -> int {
            auto rc = dpu_app->respondCmd(buf, size);
            return rc == android::trusty::TrustyAppError::OK ? 0 : 1;
        });
    if (!dpu_handler) return EXIT_FAILURE;  // TeeuiRc::SystemError

    /* main loop */
    while (1) {
      auto [result, read_len] = dpu_app->getCmd(buf, sizeof(buf));
      if (result == android::trusty::TrustyAppError::OK) {
        auto [rc, err_msg] = dpu_handler->handle(buf, read_len);
        if (rc) {
          LOG(ERROR) << err_msg;
        }
      } else {
        LOG(ERROR) << "Failed to get message to TrustyApp";
      }
    }
    LOG(ERROR) << "exiting securedpud loop";

    return EXIT_FAILURE;
}
