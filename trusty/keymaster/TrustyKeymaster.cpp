/*
 * Copyright 2018 The Android Open Source Project
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

#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/keymaster_configuration.h>
#include <trusty_keymaster/TrustyKeymaster.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

namespace keymaster {

int TrustyKeymaster::Initialize() {
    int err;

    err = trusty_keymaster_connect();
    if (err) {
        ALOGE("Failed to connect to trusty keymaster %d", err);
        return err;
    }

    ConfigureRequest req;
    req.os_version = GetOsVersion();
    req.os_patchlevel = GetOsPatchlevel();

    ConfigureResponse rsp;
    Configure(req, &rsp);

    if (rsp.error != KM_ERROR_OK) {
        ALOGE("Failed to configure keymaster %d", rsp.error);
        return -1;
    }

    return 0;
}

TrustyKeymaster::TrustyKeymaster() {}

TrustyKeymaster::~TrustyKeymaster() {
    trusty_keymaster_disconnect();
}

void TrustyKeymaster::ForwardCommand(enum keymaster_command command, const Serializable& req,
                                     KeymasterResponse* rsp) {
    keymaster_error_t err;
    err = trusty_keymaster_send(command, req, rsp);
    if (err != KM_ERROR_OK) {
        ALOGE("Failed to send cmd %d err: %d", command, err);
        rsp->error = err;
    }
}

}  // namespace keymaster
