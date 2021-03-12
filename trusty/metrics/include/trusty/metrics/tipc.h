/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

/**
 * DOC: Metrics
 *
 * Metrics interface provides a way for Android to get Trusty metrics data.
 *
 * Currently, only "push" model is supported. Clients are expected to connect to
 * metrics service and listen for events, e.g. app crash events.
 *
 * In the future, if we need to have Android "pull" metrics data from Trusty,
 * that can be done by introducing a separate port.
 *
 * This interface is shared between Android and Trusty. There is a copy in each
 * repository. They must be kept in sync.
 */

#define METRICS_PORT "com.android.trusty.metrics"

/**
 * enum metrics_cmd - command identifiers for metrics interface
 * @METRICS_CMD_CRASH_REPORT: report an app crash
 */
enum metrics_cmd {
    METRICS_CMD_CRASH_REPORT = 1U,
};

/**
 * struct metrics_hdr - common structure for metrics messages
 * @cmd: command identifier - one of &enum metrics_cmd
 */
struct metrics_hdr {
    uint32_t cmd;
} __attribute__((__packed__));

/**
 * struct metrics_crash_report_args - arguments of a crash report message
 * @app_id_len: length of app ID that follows this structure
 */
struct metrics_crash_report_args {
    uint32_t app_id_len;
} __attribute__((__packed__));

#define METRICS_MAX_APP_ID_LEN 256

#define METRICS_MAX_MSG_SIZE                                                 \
    (sizeof(struct metrics_hdr) + sizeof(struct metrics_crash_report_args) + \
     METRICS_MAX_APP_ID_LEN)
