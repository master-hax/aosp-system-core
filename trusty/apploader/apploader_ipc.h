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

#define APPLOADER_PORT "com.android.trusty.apploader"

enum apploader_command {
    APPLOADER_REQ_SHIFT = 1,
    APPLOADER_RESP_BIT = 1,

    APPLOADER_CMD_LOAD_APPLICATION = (0 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_GET_VERSION = (1 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_UNLOAD_APPLICATION = (2 << APPLOADER_REQ_SHIFT),
};

enum apploader_error {
    APPLOADER_NO_ERROR = 0,
    APPLOADER_ERR_INVALID_CMD,
};

/**
 * apploader_header - Serial header for communicating with apploader
 * @cmd: the command; one of enum apploader_command values.
 */
struct apploader_header {
    uint32_t cmd;
};

/**
 * apploader_load_req - Serial arguments for LOAD_APPLICATION command
 * @package_size: size of the application package.
 */
struct apploader_load_req {
    uint64_t package_size;
};

/**
 * apploader_req - Common structure for all apploader requests
 * @hdr - header with command value.
 * @load_req - arguments for LOAD_APPLICATION command.
 */
struct apploader_req {
    struct apploader_header hdr;
    union {
        struct apploader_load_req load_req;
    };
};

/**
 * apploader_resp - Common structure for all apploader responses
 * @hdr - header with command value.
 * @error - error code returned by peer; one of enum apploader_error values.
 */
struct apploader_resp {
    struct apploader_header hdr;
    uint32_t error;
};
