/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <stdint.h>

#define COVERAGE_CLIENT_PORT "com.android.trusty.coverage.client"

struct uuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_and_node[8];
};

enum coverage_client_cmd {
    COVERAGE_CLIENT_CMD_RESP_BIT = 1U,
    COVERAGE_CLIENT_CMD_SHIFT = 1U,
    COVERAGE_CLIENT_CMD_OPEN = (1U << COVERAGE_CLIENT_CMD_SHIFT),
    COVERAGE_CLIENT_CMD_PULL = (2U << COVERAGE_CLIENT_CMD_SHIFT),
    COVERAGE_CLIENT_CMD_RESET = (3U << COVERAGE_CLIENT_CMD_SHIFT),
};

struct coverage_client_hdr {
    uint32_t cmd;
};

struct coverage_client_open_args {
    struct uuid uuid;
    uint32_t shm_len;
};
