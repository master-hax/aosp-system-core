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
    APPLOADER_ERR_BAD_HANDLE,
    APPLOADER_ERR_NO_MEMORY,
    APPLOADER_ERR_BAD_PACKAGE,
    APPLOADER_ERR_INTERNAL,
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
 * apploader_resp - Common header for all apploader responses
 * @hdr - header with command value.
 * @error - error code returned by peer; one of enum apploader_error values.
 *
 * This structure is followed by the response-specific payload.
 */
struct apploader_resp {
    struct apploader_header hdr;
    uint32_t error;
};

/**
 * apploader_msg - Common structure for all apploader messages
 * @req - request structure
 * @req.hdr - request header
 * @req.load_req - request payload for LOAD_APPLICATION
 * @resp - response structure
 * @resp.resp - response header
 */
struct apploader_msg {
    union {
        struct {
            struct apploader_header hdr;
            union {
                struct apploader_load_req load_req;
            };
        } req;
        struct {
            struct apploader_resp resp;
        } resp;
    };
} __packed;
