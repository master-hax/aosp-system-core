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
 * metrics service and listen for events, e.g. app crash events. To wait for an
 * event, clients must send a %METRICS_CMD_NEXT_EVENT request. Metrics service
 * will then respond to this request when, if at all, a metrics event is
 * generated.
 *
 * Note that the type of the event is not known to the client ahead of time.
 * Clients must check @type field of &struct metrics_resp of the response
 * message to know which event was received.
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
 * @METRICS_CMD_RESP_BIT:
 *      message is a response
 * @METRICS_CMD_REQ_SHIFT:
 *      number of bits used by @METRICS_CMD_RESP_BIT
 * @METRICS_CMD_NEXT_EVENT:
 *      request next event, which may come back much later or not at all
 */
enum metrics_cmd {
    METRICS_CMD_RESP_BIT = 1,
    METRICS_CMD_REQ_SHIFT = 1,

    METRICS_CMD_NEXT_EVENT = (1 << METRICS_CMD_REQ_SHIFT),
};

/**
 * enum metrics_event_type - identifiers for event types
 * @METRICS_EVENT_TYPE_CRASH: app crash event
 */
enum metrics_event_type {
    METRICS_EVENT_TYPE_CRASH = 1,
};

/**
 * struct metrics_req - common structure for metrics requests
 * @cmd: command identifier - one of &enum metrics_cmd
 */
struct metrics_req {
    uint32_t cmd;
} __attribute__((__packed__));

/**
 * struct metrics_resp - common structure for metrics responses
 * @cmd:  command identifier - one of &enum metrics_cmd
 * @type: event type identifier - one of &enum metrics_event_type
 * @idx:  index of the event, can be used to tell if events were dropped
 */
struct metrics_resp {
    uint32_t cmd;
    uint32_t type;
    uint64_t idx;
} __attribute__((__packed__));

/**
 * struct metrics_crash_report_args - arguments of a crash report message
 * @app_id_len: length of app ID that follows this structure
 */
struct metrics_crash_event_resp {
    uint32_t app_id_len;
} __attribute__((__packed__));

#define METRICS_MAX_APP_ID_LEN 256

#define METRICS_MAX_MSG_SIZE                                                 \
    (sizeof(struct metrics_resp) + sizeof(struct metrics_crash_event_resp) + \
     METRICS_MAX_APP_ID_LEN)
