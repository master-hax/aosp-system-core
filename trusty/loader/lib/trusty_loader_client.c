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

#include "trusty_loader_client.h"

#include <trusty/interface/loader.h>

#include <stdio.h>

static inline int is_lc_hex(char c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

static int validate_uuid(const char* uuid_str) {
    int null_idx;

    for (null_idx = 0; null_idx < LOADER_UUID_STR_SIZE; null_idx++) {
        if (!uuid_str[null_idx]) {
            break;
        }
    }

    if (null_idx != LOADER_UUID_STR_SIZE - 1) {
        return 0;
    }

    for (int i = 0; i < LOADER_UUID_STR_SIZE - 1; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (uuid_str[i] != '-') {
                return 0;
            }
        } else {
            if (!is_lc_hex(uuid_str[i])) {
                return 0;
            }
        }
    }

    return 1;
}

static int do_send_recv(struct tipc_obj* obj, const void* data, int data_size, void* rsp,
                        int rsp_size) {
    int rc;

    rc = obj->send(obj, data, data_size);
    if (rc != data_size) {
        return TRUSTY_LOADER_ERR_IPC;
    }

    rc = obj->recv(obj, rsp, rsp_size);
    if (rc < 0) {
        return TRUSTY_LOADER_ERR_IPC;
    }

    if (rc != rsp_size) {
        return TRUSTY_LOADER_ERR_INVALID_RSP;
    }

    return TRUSTY_LOADER_NO_ERROR;
}

static int trusty_loader_call(struct tipc_obj* obj, const struct loader_req* req,
                              const void* payload, int payload_size, struct loader_rsp* rsp) {
    int rc;
    int bytes_sent = 0;
    int msg_size;
    int max_msg_size;

    max_msg_size = obj->get_max_msg_size(obj);

    rc = do_send_recv(obj, req, sizeof(struct loader_req), rsp, sizeof(struct loader_rsp));
    if (rc != TRUSTY_LOADER_NO_ERROR) {
        return rc;
    }

    while (payload_size) {
        msg_size = payload_size > max_msg_size ? max_msg_size : payload_size;
        rc = do_send_recv(obj, (char*)payload + bytes_sent, msg_size, rsp,
                          sizeof(struct loader_rsp));
        if (rc != TRUSTY_LOADER_NO_ERROR) {
            return rc;
        }

        if (rsp->err != LOADER_NO_ERROR) {
            break;
        }

        bytes_sent += msg_size;
        payload_size -= msg_size;
    }

    return TRUSTY_LOADER_NO_ERROR;
}

static int trusty_loader_cmd(struct tipc_obj* obj, int cmd, const void* payload, int payload_size,
                             int* rsp) {
    int rc;
    struct loader_req request;
    struct loader_rsp response;

    request.cmd = cmd;
    request.payload_size = payload_size;

    rc = trusty_loader_call(obj, &request, payload, payload_size, &response);

    if (rc == TRUSTY_LOADER_NO_ERROR) {
        *rsp = response.err;
    }

    return rc;
}

int trusty_loader_load(struct tipc_obj* obj, const void* app_data, int app_size, int* rsp) {
    return trusty_loader_cmd(obj, LOADER_CMD_LOAD, app_data, app_size, rsp);
}

int trusty_loader_unload(struct tipc_obj* obj, const char* app_uuid, int* rsp) {
    if (!validate_uuid(app_uuid)) {
        return TRUSTY_LOADER_ERR_INVALID_ARGS;
    }

    return trusty_loader_cmd(obj, LOADER_CMD_UNLOAD, app_uuid, LOADER_UUID_STR_SIZE, rsp);
}
