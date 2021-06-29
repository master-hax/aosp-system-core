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

// All functions declared in this header build a keymaster structs from a protobuf description. If
// the function may produce keymaster structs that are likely to crash the test harness (e.g. the
// protobuf input is missing a required field), then it will return a bool to signify if the struct
// can be used reliably. Returning `false` means that the test case should be skipped to avoid
// having to restart the fuzzer. Note that although returning `true` means the struct is unlikely to
// crash the test harness, it may be invalid and still has the potential to find interesting
// behavior in trusty.

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

void BuildGenKeyAuthorizationSet(keymaster::AuthorizationSet& set);

void BuildBeginOpAuthorizationSet(const fuzz::AuthorizationSet& proto_set,
                                  keymaster::AuthorizationSet& set);
