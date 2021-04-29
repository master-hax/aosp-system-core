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

#include <fuzz/keymaster_fuzzer.pb.h>
#include <keymaster/android_keymaster.h>
#include <src/libfuzzer/libfuzzer_macro.h>
#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/coverage/uuid.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <trusty_keymaster/ipc/keymaster_ipc.h>
#include <unistd.h>
#include <iostream>
#include <memory>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;
namespace fuzz = android::trusty::keymaster::fuzz;

#define TIPC_DEV "/dev/trusty-ipc-dev0"

#define TRUSTY_APP_PORT "com.android.trusty.keymaster"
#define TRUSTY_APP_UUID "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
#define TRUSTY_APP_FILENAME "keymaster.syms.elf"

static std::unique_ptr<CoverageRecord> record;

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    uuid module_uuid;

    if (!str_to_uuid(TRUSTY_APP_UUID, &module_uuid)) {
        std::cerr << "Failed to parse UUID: " << TRUSTY_APP_UUID << std::endl;
        exit(-1);
    }

    /* Make sure lazy-loaded TAs have started and connected to coverage service. */
    TrustyApp ta(TIPC_DEV, TRUSTY_APP_PORT);
    auto ret = ta.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }

    record = std::make_unique<CoverageRecord>(TIPC_DEV, &module_uuid, TRUSTY_APP_FILENAME);
    if (!record) {
        std::cerr << "Failed to allocate coverage record" << std::endl;
        exit(-1);
    }

    ret = record->Open();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }
    return 0;
}

static uint32_t MessageCmdToKeymasterCmd(const fuzz::Request::MessageCmdCase cmd) {
    switch (cmd) {
        case fuzz::Request::kGenerateKeyRequest:
            return KM_GENERATE_KEY;
        default:
            return static_cast<uint32_t>(cmd);
    }
}

static void BuildAuthorizationSet(keymaster::AuthorizationSet& set,
                                  const fuzz::AuthorizationSet& set_proto) {
    for (auto key_param_proto : set_proto.elements()) {
        keymaster_key_param_t key_param = {};
        key_param.tag = static_cast<keymaster_tag_t>(key_param_proto.tag());
        switch (key_param_proto.value_selector_case()) {
            case fuzz::KeyParam::kEnumerated:
                key_param.enumerated = key_param_proto.enumerated();
                break;
            case fuzz::KeyParam::kBoolean:
                key_param.boolean = key_param_proto.boolean();
                break;
            case fuzz::KeyParam::kInteger:
                key_param.integer = key_param_proto.integer();
                break;
            case fuzz::KeyParam::kLongInteger:
                key_param.long_integer = key_param_proto.long_integer();
                break;
            case fuzz::KeyParam::kDateTime:
                key_param.date_time = key_param_proto.date_time();
                break;
            case fuzz::KeyParam::kBlob:
                key_param.blob.data =
                        reinterpret_cast<const uint8_t*>(key_param_proto.blob().data().data());
                key_param.blob.data_length = key_param_proto.blob().data().length();
                break;
            default:
                continue;
        }
        set.push_back(key_param);
    }
}

template <typename BlobType>
static void BuildBlob(keymaster::TKeymasterBlob<BlobType>& blob, const fuzz::Blob& blob_proto) {
    if (!blob_proto.data().empty()) {
        blob = keymaster::TKeymasterBlob<BlobType>(
                reinterpret_cast<const uint8_t*>(blob_proto.data().data()),
                blob_proto.data().length());
    }
}

static android::base::Result<uint32_t> BuildPayload(uint8_t* payload, size_t payload_len,
                                                    const fuzz::Request& message) {
    switch (message.message_cmd_case()) {
        case fuzz::Request::kGenerateKeyRequest: {
            auto req_proto = message.generate_key_request();
            keymaster::GenerateKeyRequest req(message.message_version());

            BuildAuthorizationSet(req.key_description, req_proto.key_descriptor());
            BuildBlob(req.attestation_signing_key_blob, req_proto.attestation_signing_key_blob());
            BuildAuthorizationSet(req.attest_key_params, req_proto.attest_key_params());
            BuildBlob(req.issuer_subject, req_proto.issuer_subject());

            req.Serialize(payload, payload + payload_len);
            return {req.SerializedSize()};
        }
        case fuzz::Request::kBeginOperationRequest: {
            auto req_proto = message.begin_operation_request();
            keymaster::BeginOperationRequest req(message.message_version());

            req.purpose = static_cast<keymaster_purpose_t>(req_proto.purpose());
            req.SetKeyMaterial(req_proto.key_blob().data().data(),
                               req_proto.key_blob().data().length());
            BuildAuthorizationSet(req.additional_params, req_proto.additional_params());

            req.Serialize(payload, payload + payload_len);
            return {req.SerializedSize()};
        }
        default:
            return Errorf("Invalid keymaster message cmd: {}", message.message_cmd_case());
    }
}

DEFINE_PROTO_FUZZER(const fuzz::Transcript& transcript) {
    static uint8_t buf[KEYMASTER_MAX_BUFFER_LENGTH];

    ExtraCounters counters(record.get());
    counters.Reset();

    TrustyApp ta(TIPC_DEV, TRUSTY_APP_PORT);
    auto ret = ta.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        android::trusty::fuzz::Abort();
    }

    for (auto& message : transcript.messages()) {
        memset(buf, 0, sizeof(buf));
        struct keymaster_message* msg = reinterpret_cast<struct keymaster_message*>(buf);
        msg->cmd = MessageCmdToKeymasterCmd(message.message_cmd_case());
        auto msg_size =
                BuildPayload(msg->payload, KEYMASTER_MAX_BUFFER_LENGTH - sizeof(msg->cmd), message);
        if (!msg_size.ok()) {
            return;
        }

        ret = ta.Write(buf, *msg_size);
        if (!ret.ok()) {
            return;
        }

        ret = ta.Read(&buf, sizeof(buf));
        if (!ret.ok()) {
            return;
        }
    }
}
