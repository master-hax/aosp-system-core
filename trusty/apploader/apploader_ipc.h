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

#define APPLOADER_PORT "com.android.trusty.apploader"

enum apploader_command {
    APPLOADER_LOAD_APPLICATION,
    APPLOADER_GET_VERSION,
    APPLOADER_UNLOAD_APPLICATION,

    /*
     * Secure world-only commands
     */
    APPLOADER_SEC_SECURE_GET_MEMORY,
    APPLOADER_SEC_ABORT_LOAD,
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
