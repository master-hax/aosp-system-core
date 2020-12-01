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
#define APPLOADER_SECURE_PORT "com.android.trusty.apploader.secure"

enum apploader_command {
    APPLOADER_REQ_SHIFT = 1,
    APPLOADER_RESP_BIT = 1,

    APPLOADER_CMD_LOAD_APPLICATION = (0 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_GET_VERSION = (1 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_UNLOAD_APPLICATION = (2 << APPLOADER_REQ_SHIFT),

    /**
     * Secure world-only commands
     */
    APPLOADER_CMD_SEC_SECURE_GET_MEMORY = (0x1000 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_SEC_ABORT_LOAD = (0x1001 << APPLOADER_REQ_SHIFT),
};

enum apploader_error {
    APPLOADER_NO_ERROR = 0,
    APPLOADER_ERR_INVALID_CMD,
};

/**
 * apploader_message - Serial header for communicating with apploader
 * @cmd: the command, one of the apploader_command values.
 * @payload: start of the serialized command specific payload
 */
struct apploader_message {
    uint32_t cmd;
    uint8_t payload[0];
};

/**
 * apploader_response - Serial header for response from apploader
 * @cmd: the command, one of the apploader_command values.
 * @error: the error, one of the apploader_error values.
 */
struct apploader_response {
    uint32_t cmd;
    uint32_t error;
};
