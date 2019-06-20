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

#ifdef __cplusplus
extern "C" {
#endif

enum trusty_loader_err {
    TRUSTY_LOADER_NO_ERROR,
    TRUSTY_LOADER_ERR_IPC,
    TRUSTY_LOADER_ERR_INVALID_RSP,
    TRUSTY_LOADER_ERR_INVALID_ARGS,
};

struct tipc_obj {
    int (*get_max_msg_size)(struct tipc_obj* obj);
    int (*send)(struct tipc_obj* obj, const void* data, int size);
    int (*recv)(struct tipc_obj* obj, void* data, int size);
};

int trusty_loader_load(struct tipc_obj* obj, const void* app_data, int app_size, int* rsp);
int trusty_loader_unload(struct tipc_obj* obj, const char* app_uuid, int* rsp);

#ifdef __cplusplus
}
#endif
