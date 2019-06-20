/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define TIPC_HEADER_SIZE (16)
#define MAX_TIPC_PAYLOAD_SIZE (PAGE_SIZE - TIPC_HEADER_SIZE)

__BEGIN_DECLS

enum loader_error {
    NO_ERROR,
    ERR_TIMEOUT,
    ERR_INPUT,
    ERR_TIPC,
    ERR_SERVER,
    ERR_INVALID_ARGS,
    ERR_APP_NOT_FOUND,
    ERR_APP_EXISTS,
    ERR_APP_RUNNING,
    ERR_NO_MEM,
    ERR_INVALID_RSP,
    ERR_INTERNAL,
};

int loader_load(const char* dev_name, const char* file_name);
int loader_unload(const char* dev_name, const char* uuid_str);
const char* loader_error_to_str(int rsp);

__END_DECLS
