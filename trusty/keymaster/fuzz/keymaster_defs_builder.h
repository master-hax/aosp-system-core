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

#pragma once

#include <fuzz/keymaster_fuzzer.pb.h>
#include <keymaster/android_keymaster.h>
#include <unistd.h>

namespace fuzz = android::trusty::keymaster::fuzz;

// All functions declared in this header build keymaster_defs.h structs, possibly with some
// invariants, from a protobuf description of the struct returning `true` if a struct which will
// probably not crash the test harness was built.

enum Invariant {
    GenerateKey,
    BeginOp,
};

template <typename BlobType>
void BuildBlob(const fuzz::Blob& proto_blob, keymaster::TKeymasterBlob<BlobType>& blob) {
    if (!proto_blob.data().empty()) {
        blob = keymaster::TKeymasterBlob<BlobType>(
                reinterpret_cast<const uint8_t*>(proto_blob.data().data()),
                proto_blob.data().length());
    }
}

void BuildBlob(const fuzz::Blob& proto_blob, keymaster_key_blob_t& blob);

bool BuildBuffer(const fuzz::Buffer& proto_buffer, keymaster::Buffer& buffer);

void BuildAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                           keymaster::AuthorizationSet& set);

void BuildAuthorizationSet(keymaster::AuthorizationSet& set, Invariant invariant);

void BuildAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                           keymaster::AuthorizationSet& set, Invariant invariant);
