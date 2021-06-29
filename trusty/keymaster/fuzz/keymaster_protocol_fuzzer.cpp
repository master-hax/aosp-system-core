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
#include "keymaster_defs_builder.h"

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;
namespace fuzz = android::trusty::keymaster::fuzz;

#define TIPC_DEV "/dev/trusty-ipc-dev0"

#define TRUSTY_APP_PORT "com.android.trusty.keymaster"
#define TRUSTY_APP_UUID "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
#define TRUSTY_APP_FILENAME "keymaster.syms.elf"

template <typename T>
struct Message {
    static const uint32_t cmd;
};
#define MAP_CMD_TO_REQ(command, value)                \
    template <>                                       \
    struct Message<keymaster::command##Request> {     \
        static const uint32_t cmd = value;            \
        typedef fuzz::command##Request proto_ty;      \
        typedef keymaster::command##Response resp_ty; \
    }

MAP_CMD_TO_REQ(GenerateKey, 0);
MAP_CMD_TO_REQ(BeginOperation, 1);
MAP_CMD_TO_REQ(UpdateOperation, 2);
MAP_CMD_TO_REQ(FinishOperation, 3);

static TrustyApp kTrustyApp(TIPC_DEV, TRUSTY_APP_PORT);
static std::unique_ptr<CoverageRecord> record;

static int32_t version = static_cast<int32_t>(keymaster::KmVersion::KEYMASTER_4);
static uint8_t buf[KEYMASTER_MAX_BUFFER_LENGTH];
static uint64_t total_cases = 0;
static uint64_t failed_cases = 0;

extern keymaster_blob_t app_id;
extern keymaster_blob_t app_data;
static keymaster::GenerateKeyResponse gen_key_resp(version);

extern void BuildAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                                  keymaster::AuthorizationSet& set, Invariant invariant);
extern void BuildAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                                  keymaster::AuthorizationSet& set);
template <typename BlobType>
void BuildBlob(const fuzz::Blob& proto_blob, keymaster::TKeymasterBlob<BlobType>& blob) {
    if (!proto_blob.data().empty()) {
        blob = keymaster::TKeymasterBlob<BlobType>(
                reinterpret_cast<const uint8_t*>(proto_blob.data().data()),
                proto_blob.data().length());
    }
}

void BuildBlob(const fuzz::Blob& proto_blob, keymaster_key_blob_t& blob) {
    if (!proto_blob.data().empty()) {
        blob.key_material = reinterpret_cast<const uint8_t*>(proto_blob.data().data());
        blob.key_material_size = proto_blob.data().length();
    }
}

bool BuildBuffer(const fuzz::Buffer& proto_buffer, keymaster::Buffer& buffer) {
    if (!proto_buffer.blob().data().empty()) {
        buffer = keymaster::Buffer(
                reinterpret_cast<const uint8_t*>(proto_buffer.blob().data().data()),
                proto_buffer.blob().data().length());
        buffer.advance_read(proto_buffer.read_pos());
        buffer.advance_write(proto_buffer.write_pos());
        return true;
    } else {
        return false;
    }
}

static void BuildGenerateKeyMsg(const fuzz::GenerateKeyRequest& proto_req,
                                keymaster::GenerateKeyRequest& req) {
    BuildAuthorizationSet(proto_req.key_description(), req.key_description, Invariant::GenerateKey);
    BuildBlob(proto_req.attestation_signing_key_blob(), req.attestation_signing_key_blob);
    BuildAuthorizationSet(proto_req.attest_key_params(), req.attest_key_params);
    BuildBlob(proto_req.issuer_subject(), req.issuer_subject);
}

template <typename Request>
static bool SendMessage(const Request& req, typename Message<Request>::resp_ty& resp) {
    memset(buf, 0, sizeof(buf));
    struct keymaster_message* msg = reinterpret_cast<struct keymaster_message*>(buf);

    msg->cmd = Message<Request>::cmd << KEYMASTER_REQ_SHIFT;
    req.Serialize(msg->payload, msg->payload + KEYMASTER_MAX_BUFFER_LENGTH - sizeof(msg->cmd));

    size_t msg_size = req.SerializedSize();

    auto ret = kTrustyApp.Write(buf, msg_size);
    if (!ret.ok()) {
        return false;
    }
    ret = kTrustyApp.Read(&buf, sizeof(buf));
    if (!ret.ok()) {
        return false;
    }
    const uint8_t* payload = msg->payload;
    if (!resp.Deserialize(&payload,
                          msg->payload + KEYMASTER_MAX_BUFFER_LENGTH - sizeof(msg->cmd))) {
        return false;
    }
    return true;
}

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
    fuzz::GenerateKeyRequest proto_gen_key_req;
    // TODO: Add a signing key blob to gen_key_req
    keymaster::GenerateKeyRequest gen_key_req(version);

    BuildGenerateKeyMsg(proto_gen_key_req, gen_key_req);
    if (!SendMessage(gen_key_req, gen_key_resp)) {
        return -1;
    }
    if (gen_key_resp.error != KM_ERROR_OK) {
        LOG("Failed to generate key (%d)", gen_key_resp.error);
        return gen_key_resp.error;
    }
    LOG("Generated key successfully (%d)\n", gen_key_resp.error);

    return 0;
}

static void BuildBeginOpMsg(const fuzz::BeginOperationRequest& proto_req,
                            keymaster::BeginOperationRequest& req) {
    /// This is currently specific to the BeginOp cmd in the first signing test
    // req.purpose = static_cast<keymaster_purpose_t>(proto_req.purpose());
    // BuildBlob(proto_req.key_blob(), req.key_blob);
    req.purpose = KM_PURPOSE_SIGN;
    req.key_blob = gen_key_resp.key_blob;
    BuildAuthorizationSet(proto_req.additional_params(), req.additional_params, Invariant::BeginOp);
}

static bool BuildUpdateOpMsg(const fuzz::UpdateOperationRequest& proto_req,
                             keymaster::UpdateOperationRequest& req) {
    req.op_handle = proto_req.op_handle();
    if (!BuildBuffer(proto_req.input(), req.input)) {
        return false;
    }
    BuildAuthorizationSet(proto_req.additional_params(), req.additional_params);
    return true;
}

static bool BuildFinishOpMsg(const fuzz::FinishOperationRequest& proto_req,
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

// Sends the given signing test commands to trusty. Returns the error code returned by the first
// failed command or nullopt if signing test failed for another reason (e.g. the protobuf test had
// empty buffers for blobs that shouldn't be empty)
static std::optional<keymaster_error_t> TestSigning(const fuzz::SigningTest& proto_test) {
    auto proto_begin_req = proto_test.begin_op();
    std::unique_ptr<keymaster::BeginOperationRequest> begin_req(
            new keymaster::BeginOperationRequest(version));
    std::unique_ptr<keymaster::BeginOperationResponse> begin_resp(
            new keymaster::BeginOperationResponse(version));

    BuildBeginOpMsg(proto_begin_req, *begin_req);
    if (!SendMessage(*begin_req, *begin_resp)) {
        return {};
    }
    begin_req->key_blob.key_material = NULL;
    LOG("begin: %d\n", begin_resp->error);
    if (begin_resp->error != KM_ERROR_OK) {
        // TODO: Send abort command to keymaster before returning here
        return begin_resp->error;
    }

    auto proto_update_req = proto_test.update_op();
    std::unique_ptr<keymaster::UpdateOperationRequest> update_req(
            new keymaster::UpdateOperationRequest(version));
    std::unique_ptr<keymaster::UpdateOperationResponse> update_resp(
            new keymaster::UpdateOperationResponse(version));

    if (!BuildUpdateOpMsg(proto_update_req, *update_req)) {
        return {};
    }
    update_req->op_handle = begin_resp->op_handle;
    if (!SendMessage(*update_req, *update_resp)) {
        return {};
    }
    LOG("update: %d\n", begin_resp->error);
    if (update_resp->error != KM_ERROR_OK) {
        // TODO: Send abort command to keymaster before returning here
        return update_resp->error;
    }

    auto proto_finish_req = proto_test.finish_op();
    std::unique_ptr<keymaster::FinishOperationRequest> finish_req(
            new keymaster::FinishOperationRequest(version));
    std::unique_ptr<keymaster::FinishOperationResponse> finish_resp(
            new keymaster::FinishOperationResponse(version));

    if (!BuildFinishOpMsg(proto_finish_req, *finish_req)) {
        return {};
    }
    finish_req->op_handle = begin_resp->op_handle;
    if (!SendMessage(*finish_req, *finish_resp)) {
        return {};
    }
    LOG("finish: %d\n", begin_resp->error);
    return finish_resp->error;
}

DEFINE_PROTO_FUZZER(fuzz::Test& test) {
    ExtraCounters counters(record.get());
    counters.Reset();

    if (test.test_case() != 0) {
        total_cases += 1;
        std::optional<keymaster_error_t> err = {};
        switch (test.test_case()) {
            case fuzz::Test::kSigningTest: {
                PROTO_DEBUG(test);
                err = TestSigning(test.signing_test());
                break;
            }
            default: {
                ABORT("Hit unreachable test case\n");
            }
        }
        if (err != KM_ERROR_OK) {
            failed_cases += 1;
        }
        if (total_cases != 0) {
            LOG("%lu / %lu = %f%% cases failed\n", failed_cases, total_cases,
                100.0 * (double)failed_cases / (double)total_cases);
        }
    }
}
