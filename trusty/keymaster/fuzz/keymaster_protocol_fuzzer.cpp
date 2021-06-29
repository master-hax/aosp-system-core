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
#include <fuzz/keymaster_fuzzer.pb.h>
#include <fuzz/requests_builder.h>
#include <hardware/keymaster_defs.h>
#include <keymaster/android_keymaster.h>
#include <src/libfuzzer/libfuzzer_macro.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <trusty_keymaster/ipc/keymaster_ipc.h>
#include <unistd.h>
#include <iostream>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;
namespace fuzz = android::trusty::keymaster::fuzz;

#define TIPC_DEV "/dev/trusty-ipc-dev0"

#define TRUSTY_APP_PORT "com.android.trusty.keymaster"
#define TRUSTY_APP_UUID "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
#define TRUSTY_APP_FILENAME "keymaster.syms.elf"

// Maps a keymaster request to the corresponding keymaster response and command code. Instances must
// contain a typedef named `resp_type` for the response. The command codes are defined in
// trusty/user/app/keymaster/ipc/keymaster_ipc.h but don't include the shift by KEYMASTER_REQ_SHIFT.
template <typename T>
struct Message {
    static const uint32_t cmd_code;
};

// Defines `Message` for keymaster commands given the common prefix of the keymaster request and
// response names and the command code.
#define DEF_MESSAGE(command, code)                      \
    template <>                                         \
    struct Message<keymaster::command##Request> {       \
        static const uint32_t cmd_code = code;          \
        typedef keymaster::command##Response resp_type; \
    }

DEF_MESSAGE(GenerateKey, 0);
DEF_MESSAGE(BeginOperation, 1);
DEF_MESSAGE(UpdateOperation, 2);
DEF_MESSAGE(FinishOperation, 3);

#undef INST_MESSAGE

static TrustyApp kTrustyApp(TIPC_DEV, TRUSTY_APP_PORT);
static std::unique_ptr<CoverageRecord> record;

static int32_t version = static_cast<int32_t>(keymaster::KmVersion::KEYMASTER_4);
static uint8_t buf[KEYMASTER_MAX_BUFFER_LENGTH];

// A key generated when initializing the fuzzer to prevent having to generate one for every test
// case. Test cases may use either this initial key blob or generate their own from a protobuf
// request.
keymaster::KeymasterKeyBlob initial_key_blob;

// Sends a request to keymaster returning `true` if a valid response was received.
template <typename Request>
static bool SendMessage(const Request& req, typename Message<Request>::resp_type& resp) {
    memset(buf, 0, sizeof(buf));
    struct keymaster_message* msg = reinterpret_cast<struct keymaster_message*>(buf);

    // They keymaster request `req` doesn't include a command code so we need to serialize the
    // corresponding code into the buffer separately.
    msg->cmd = Message<Request>::cmd_code << KEYMASTER_REQ_SHIFT;

    // Write the rest of the request into the buffer
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
    return resp.Deserialize(&payload,
                            msg->payload + KEYMASTER_MAX_BUFFER_LENGTH - sizeof(msg->cmd));
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

    // Generate a key to use for all signing tests
    static keymaster::GenerateKeyRequest gen_key_req(version);
    static keymaster::GenerateKeyResponse gen_key_resp(version);
    static std::string_view key_blob(__TIME__);

    gen_key_req.attestation_signing_key_blob.key_material =
            keymaster::dup_buffer(key_blob.data(), key_blob.size());
    gen_key_req.attestation_signing_key_blob.key_material_size = key_blob.size();
    BuildGenKeyAuthorizationSet(gen_key_req.key_description);

    if (!SendMessage(gen_key_req, gen_key_resp)) {
        std::cerr << "Failed to send initial generate key message to keymaster" << std::endl;
        exit(-1);
    }

    if (gen_key_resp.error != KM_ERROR_OK) {
        std::cerr << "Failed to generate an initial key " << gen_key_resp.error << std::endl;
        exit(-1);
    }
    initial_key_blob = gen_key_resp.key_blob;
    std::cout << "Generated an initial key successfully" << std::endl;

    return 0;
}

// TODO: Send abort commands to keymaster before returning from a failed begin/update command
// Sends a random signing test to trusty. Returns the error code returned by the first command to
// fail or nullopt for tests that fail or are likely to fail in the fuzzing harness.
static std::optional<keymaster_error_t> TestSigning(const fuzz::SigningTest& proto_test) {
    // Send a begin operation request and get an op handle for the tests
    auto proto_begin_req = proto_test.begin_op();
    keymaster::BeginOperationRequest begin_req(version);
    keymaster::BeginOperationResponse begin_resp(version);

    BuildBeginOpSignMsg(proto_begin_req, begin_req);
    if (!SendMessage(begin_req, begin_resp)) {
        return {};
    }

    // Send an update operation request using the previous op handle
    auto proto_update_req = proto_test.update_op();
    keymaster::UpdateOperationRequest update_req(version);
    keymaster::UpdateOperationResponse update_resp(version);

    if (!BuildUpdateOpMsg(proto_update_req, update_req)) {
        return {};
    }
    // Op handle must be set after building an initial update request from the protobuf request
    update_req.op_handle = begin_resp.op_handle;
    if (!SendMessage(update_req, update_resp)) {
        return {};
    }

    // Send a finish operation request using the previous op handle
    auto proto_finish_req = proto_test.finish_op();
    keymaster::FinishOperationRequest finish_req(version);
    keymaster::FinishOperationResponse finish_resp(version);

    if (!BuildFinishOpMsg(proto_finish_req, finish_req)) {
        return {};
    }
    // Op handle must be set after building an initial finish request from the protobuf request
    finish_req.op_handle = begin_resp.op_handle;
    if (!SendMessage(finish_req, finish_resp)) {
        return {};
    }

    return finish_resp.error;
}

DEFINE_PROTO_FUZZER(fuzz::Test& test) {
    ExtraCounters counters(record.get());
    counters.Reset();

    switch (test.test_case()) {
        case fuzz::Test::kSigningTest: {
            TestSigning(test.signing_test());
            break;
        }
        default: {
            break;
        }
    }

    // Reconnect to the service to ensure it's still up
    kTrustyApp.Disconnect();
    auto ret = kTrustyApp.Connect();
    if (!ret.ok()) {
        std::cerr << ret.error() << std::endl;
        exit(-1);
    }
}
