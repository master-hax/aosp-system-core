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

#include <fuzz/keymaster_defs_builder.h>
#include <fuzz/keymaster_fuzzer.pb.h>
#include <keymaster/android_keymaster.h>

namespace fuzz = android::trusty::keymaster::fuzz;

// All functions declared in this header build a keymaster request from a protobuf request. If the
// function may produce keymaster requests that are likely to crash the test harness (e.g. the
// protobuf input is missing a required field), then it will return a bool to signify if the request
// can be used reliably. Returning `false` means that the test case should be skipped to avoid
// having to restart the fuzzer. Note that although returning `true` means the request is unlikely
// to crash the test harness, it may be invalid and still has the potential to find interesting
// behavior in trusty.

void BuildGenKeyMsg(const fuzz::GenerateKeyRequest& proto_req, keymaster::GenerateKeyRequest& req);

void BuildBeginOpMsg(const fuzz::BeginOperationRequest& proto_req,
                     keymaster::BeginOperationRequest& req);

// Builds a `BeginOperationRequest` from a protobuf request with purpose set to `KM_PURPOSE_SIGN`.
void BuildBeginOpSignMsg(const fuzz::BeginOperationRequest& proto_req,
                         keymaster::BeginOperationRequest& req);

bool BuildUpdateOpMsg(const fuzz::UpdateOperationRequest& proto_req,
                      keymaster::UpdateOperationRequest& req);

bool BuildFinishOpMsg(const fuzz::FinishOperationRequest& proto_req,
                      keymaster::FinishOperationRequest& req);
