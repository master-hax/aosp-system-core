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
#include <hardware/keymaster_defs.h>
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

static TrustyApp kTrustyApp(TIPC_DEV, TRUSTY_APP_PORT);
static std::unique_ptr<CoverageRecord> record;

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    uuid module_uuid;

    if (!str_to_uuid(TRUSTY_APP_UUID, &module_uuid)) {
        std::cerr << "Failed to parse UUID: " << TRUSTY_APP_UUID << std::endl;
        exit(-1);
    }

    /* Make sure lazy-loaded TAs have started and connected to coverage service. */
    auto ret = kTrustyApp.Connect();
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

static void BuildAuthorizationSet(keymaster::AuthorizationSet& set,
                                  const fuzz::AuthorizationSet& set_proto) {
    for (auto key_param_proto : set_proto.elements()) {
        keymaster_key_param_t key_param = {};
        switch (key_param_proto.tagged_value_case()) {
            case fuzz::KeyParam::kEnumerated: {
                auto tag_type = KM_ENUM;
                if (key_param_proto.tag_repeats()) {
                    tag_type = KM_ENUM_REP;
                }
                switch (key_param_proto.enumerated().value_case()) {
                    case fuzz::KeyParam::TaggedEnum::kPurpose:
                        key_param.enumerated = key_param_proto.enumerated().purpose();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_PURPOSE);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kAlgorithm:
                        key_param.enumerated = key_param_proto.enumerated().algorithm();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_ALGORITHM);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kBlockMode:
                        key_param.enumerated = key_param_proto.enumerated().block_mode();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_BLOCK_MODE);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kDigest:
                        key_param.enumerated = key_param_proto.enumerated().digest();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_DIGEST);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kPadding:
                        key_param.enumerated = key_param_proto.enumerated().padding();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_PADDING);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kKdf:
                        key_param.enumerated = key_param_proto.enumerated().kdf();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_KDF);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kEcCurve:
                        key_param.enumerated = key_param_proto.enumerated().ec_curve();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_EC_CURVE);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kKeyBlobUsageReqs:
                        key_param.enumerated = key_param_proto.enumerated().key_blob_usage_reqs();
                        key_param.tag = static_cast<keymaster_tag_t>(
                                tag_type | KM_TAG_BLOB_USAGE_REQUIREMENTS);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kHwAuthType:
                        key_param.enumerated = key_param_proto.enumerated().hw_auth_type();
                        key_param.tag =
                                static_cast<keymaster_tag_t>(tag_type | KM_TAG_USER_AUTH_TYPE);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kKeyOrigin:
                        key_param.enumerated = key_param_proto.enumerated().key_origin();
                        key_param.tag = static_cast<keymaster_tag_t>(tag_type | KM_TAG_ORIGIN);
                        break;
                    case fuzz::KeyParam::TaggedEnum::kRsaOaepMgfDigest:
                        key_param.enumerated = key_param_proto.enumerated().rsa_oaep_mgf_digest();
                        key_param.tag =
                                static_cast<keymaster_tag_t>(tag_type | KM_TAG_RSA_OAEP_MGF_DIGEST);
                        break;
                    default:
                        break;
                }
                break;
            }
            case fuzz::KeyParam::kBoolean: {
                // Setting key_param.boolean to false may easily trigger an assertion failure
                key_param.boolean = true;  // key_param_proto.boolean().value();
                auto bool_tag = key_param_proto.boolean().tag();
                key_param.tag = static_cast<keymaster_tag_t>(KM_BOOL | bool_tag);

                break;
            }
            case fuzz::KeyParam::kInteger: {
                key_param.integer = key_param_proto.integer().value();
                auto int_tag = key_param_proto.integer().tag();
                keymaster_tag_type_t tag_type = KM_UINT;
                if (key_param_proto.tag_repeats()) {
                    tag_type = KM_UINT_REP;
                }
                key_param.tag = static_cast<keymaster_tag_t>(tag_type | int_tag);
                break;
            }
            case fuzz::KeyParam::kLongInteger: {
                key_param.long_integer = key_param_proto.long_integer().value();
                auto long_tag = key_param_proto.long_integer().tag();
                keymaster_tag_type_t tag_type = KM_ULONG;
                if (key_param_proto.tag_repeats()) {
                    tag_type = KM_ULONG_REP;
                }
                key_param.tag = static_cast<keymaster_tag_t>(tag_type | long_tag);
                break;
            }
            case fuzz::KeyParam::kDateTime: {
                key_param.date_time = key_param_proto.date_time().value();
                auto date_tag = key_param_proto.date_time().tag();
                key_param.tag = static_cast<keymaster_tag_t>(KM_DATE | date_tag);
                break;
            }
            case fuzz::KeyParam::kBlob: {
                key_param.blob.data =
                        reinterpret_cast<const uint8_t*>(key_param_proto.blob().value().data());
                key_param.blob.data_length = key_param_proto.blob().value().length();
                auto blob_tag = key_param_proto.blob().tag();
                key_param.tag = static_cast<keymaster_tag_t>(KM_BYTES | blob_tag);
                break;
            }
            case fuzz::KeyParam::kBignum: {
                key_param.blob.data =
                        reinterpret_cast<const uint8_t*>(key_param_proto.bignum().value().data());
                key_param.blob.data_length = key_param_proto.bignum().value().length();
                auto bignum_tag = key_param_proto.bignum().tag();
                key_param.tag = static_cast<keymaster_tag_t>(KM_BIGNUM | bignum_tag);
                break;
            }
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

// static void BuildBuffer(keymaster::Buffer& buffer, const fuzz::Buffer& buffer_proto) {
//    if (!buffer_proto.data().empty()) {
//        buffer = keymaster::Buffer(
//                reinterpret_cast<const uint8_t*>(buffer_proto.data().data()),
//                buffer_proto.data().length());
//    }
//}

static android::base::Result<uint32_t> BuildPayload(uint8_t* payload, size_t payload_len,
                                                    const fuzz::Request& message) {
    auto version = message.message_version();
    switch (message.message_cmd_case()) {
        case fuzz::Request::kGenerateKeyRequest: {
            auto req_proto = message.generate_key_request();
            keymaster::GenerateKeyRequest req(version);

            BuildAuthorizationSet(req.key_description, req_proto.key_description());
            BuildBlob(req.attestation_signing_key_blob, req_proto.attestation_signing_key_blob());
            BuildAuthorizationSet(req.attest_key_params, req_proto.attest_key_params());
            BuildBlob(req.issuer_subject, req_proto.issuer_subject());

            req.Serialize(payload, payload + payload_len);
            return {req.SerializedSize()};
        }
        // case fuzz::Request::kBeginOperationRequest: {
        //    auto req_proto = message.begin_operation_request();
        //    keymaster::BeginOperationRequest req(message.message_version());

        //    req.purpose = static_cast<keymaster_purpose_t>(req_proto.purpose());
        //    req.SetKeyMaterial(req_proto.key_blob().data().data(),
        //                       req_proto.key_blob().data().length());
        //    BuildAuthorizationSet(req.additional_params, req_proto.additional_params());

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        // case fuzz::Request::kUpdateOperationRequest: {
        //    auto req_proto = message.update_operation_request();
        //    keymaster::UpdateOperationRequest req(message.message_version());

        //    req.op_handle = req_proto.op_handle();
        //    BuildBuffer(req.input, req_proto.input());
        //    BuildAuthorizationSet(req.additional_params, req_proto.additional_params());

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        // case fuzz::Request::kFinishOperationRequest: {
        //    auto req_proto = message.finish_operation_request();
        //    keymaster::FinishOperationRequest req(message.message_version());

        //    req.op_handle = req_proto.op_handle();
        //    BuildBuffer(req.input, req_proto.input());
        //    BuildBuffer(req.signature, req_proto.signature());
        //    BuildAuthorizationSet(req.additional_params, req_proto.additional_params());

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        // case fuzz::Request::kAbortOperationRequest: {
        //    auto req_proto = message.abort_operation_request();
        //    keymaster::AbortOperationRequest req(message.message_version());

        //    req.op_handle = req_proto.op_handle();

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        // case fuzz::Request::kImportKeyRequest: {
        //    auto req_proto = message.import_key_request();
        //    keymaster::ImportKeyRequest req(version);

        //    BuildAuthorizationSet(req.key_description, req_proto.key_description());
        //    req.key_format = static_cast<keymaster_key_format_t>(req_proto.key_format());
        //    BuildBlob(req.key_data, req_proto.key_data());
        //    BuildBlob(req.attestation_signing_key_blob, req_proto.attestation_signing_key_blob());
        //    BuildAuthorizationSet(req.attest_key_params, req_proto.attest_key_params());
        //    BuildBlob(req.issuer_subject, req_proto.issuer_subject());

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        // case fuzz::Request::kExportKeyRequest: {
        //    auto req_proto = message.export_key_request();
        //    keymaster::ExportKeyRequest req(version);

        //    BuildAuthorizationSet(req.additional_params, req_proto.additional_params());
        //    req.key_format = static_cast<keymaster_key_format_t>(req_proto.key_format());

        //    // TKeymasterBlob's constructor uses dup_buffer internally, but ExportKeyRequest
        //    // uses a raw keymaster_key_blob_t so we can't use BuildBlob
        //    req.key_blob.key_material = keymaster::dup_buffer(
        //            reinterpret_cast<const uint8_t*>(req_proto.key_blob().data()),
        //            req_proto.key_blob().length());
        //    req.key_blob.key_material_size = req_proto.key_blob().length();

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        // case fuzz::Request::kAddEntropyRequest: {
        //    auto req_proto = message.add_entropy_request();
        //    keymaster::AddEntropyRequest req(version);
        //    BuildBuffer(req.random_data, req_proto.random_data());

        //    req.Serialize(payload, payload + payload_len);
        //    return {req.SerializedSize()};
        //}
        default:
            return Errorf("Invalid keymaster message cmd: {}", message.message_cmd_case());
    }
}

DEFINE_PROTO_FUZZER(const fuzz::Transcript& transcript) {
    static uint8_t buf[KEYMASTER_MAX_BUFFER_LENGTH];

    ExtraCounters counters(record.get());
    counters.Reset();

    for (auto& message : transcript.messages()) {
        memset(buf, 0, sizeof(buf));
        struct keymaster_message* msg = reinterpret_cast<struct keymaster_message*>(buf);
        msg->cmd = (static_cast<uint32_t>(message.message_cmd_case()) - 1) << KEYMASTER_REQ_SHIFT;
        auto msg_size =
                BuildPayload(msg->payload, KEYMASTER_MAX_BUFFER_LENGTH - sizeof(msg->cmd), message);
        if (!msg_size.ok()) {
            return;
        }

        auto ret = kTrustyApp.Write(buf, *msg_size);
        if (!ret.ok()) {
            return;
        }

        ret = kTrustyApp.Read(&buf, sizeof(buf));
        if (!ret.ok()) {
            return;
        }
    }

    auto ret = kTrustyApp.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        android::trusty::fuzz::Abort();
    }
}
