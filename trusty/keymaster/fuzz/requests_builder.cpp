/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <fuzz/keymaster_defs_builder.h>
#include <fuzz/requests_builder.h>

extern keymaster::KeymasterKeyBlob initial_key_blob;

void BuildGenKeyMsg(const fuzz::GenerateKeyRequest& proto_req, keymaster::GenerateKeyRequest& req) {
    BuildAuthorizationSet(proto_req.key_description(), req.key_description);
    BuildBlob(proto_req.attestation_signing_key_blob(), req.attestation_signing_key_blob);
    BuildAuthorizationSet(proto_req.attest_key_params(), req.attest_key_params);
    BuildBlob(proto_req.issuer_subject(), req.issuer_subject);
}

void BuildBeginOpMsg(const fuzz::BeginOperationRequest& proto_req,
                     keymaster::BeginOperationRequest& req) {
    req.purpose = static_cast<keymaster_purpose_t>(proto_req.purpose());
    BuildBlob(proto_req.key_blob(), req.key_blob);
    BuildAuthorizationSet(proto_req.additional_params(), req.additional_params);
}

void BuildBeginOpSignMsg(const fuzz::BeginOperationRequest& proto_req,
                         keymaster::BeginOperationRequest& req) {
    req.purpose = KM_PURPOSE_SIGN;
    req.SetKeyMaterial(initial_key_blob);
    BuildBeginOpAuthorizationSet(proto_req.additional_params(), req.additional_params);
}

bool BuildUpdateOpMsg(const fuzz::UpdateOperationRequest& proto_req,
                      keymaster::UpdateOperationRequest& req) {
    req.op_handle = proto_req.op_handle();
    if (!BuildBuffer(proto_req.input(), req.input)) {
        return false;
    }
    BuildAuthorizationSet(proto_req.additional_params(), req.additional_params);
    return true;
}

bool BuildFinishOpMsg(const fuzz::FinishOperationRequest& proto_req,
                      keymaster::FinishOperationRequest& req) {
    req.op_handle = proto_req.op_handle();
    if (!BuildBuffer(proto_req.input(), req.input)) {
        return false;
    }
    if (!BuildBuffer(proto_req.signature(), req.signature)) {
        return false;
    }
    BuildAuthorizationSet(proto_req.additional_params(), req.additional_params);
    return true;
}
