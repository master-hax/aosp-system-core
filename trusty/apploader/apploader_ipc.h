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

#define APPLOADER_MAX_MSG_SIZE 16

enum apploader_command {
    APPLOADER_REQ_SHIFT = 1,
    APPLOADER_RESP_BIT = 1,

    APPLOADER_CMD_LOAD_APPLICATION = (0 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_GET_VERSION = (1 << APPLOADER_REQ_SHIFT),
    APPLOADER_CMD_UNLOAD_APPLICATION = (2 << APPLOADER_REQ_SHIFT),
};

/**
 * Secure world-only commands
 */
enum apploader_secure_command {
    APPLOADER_SECURE_REQ_SHIFT = 1,
    APPLOADER_SECURE_RESP_BIT = 1,

    APPLOADER_SECURE_CMD_GET_MEMORY = (0 << APPLOADER_SECURE_REQ_SHIFT),
    APPLOADER_SECURE_CMD_ABORT_LOAD = (1 << APPLOADER_SECURE_REQ_SHIFT),
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

struct apploader_load_message {
    uint32_t cmd;
    uint64_t package_size;
};
static_assert(sizeof(struct apploader_load_message) <= APPLOADER_MAX_MSG_SIZE);

struct apploader_error_message {
    uint32_t cmd;
    uint32_t error;
};
static_assert(sizeof(struct apploader_error_message) <= APPLOADER_MAX_MSG_SIZE);

struct apploader_secure_get_memory_message {
    uint32_t cmd;
    uint64_t package_size;
};
static_assert(sizeof(struct apploader_secure_get_memory_message) <= APPLOADER_MAX_MSG_SIZE);
