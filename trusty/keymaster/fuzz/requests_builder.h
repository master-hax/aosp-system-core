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
#include "keymaster_defs_builder.h"

namespace fuzz = android::trusty::keymaster::fuzz;

// All functions declared in this header build a keymaster request, possibly with some invariants,
// from a protobuf description of the request returning `true` if a keymaster request which will
// probably not crash the test harness was built.

void BuildGenKeyMsg(const fuzz::GenerateKeyRequest& proto_req, keymaster::GenerateKeyRequest& req);

bool BuildBeginOpMsg(const fuzz::BeginOperationRequest& proto_req,
                     keymaster::BeginOperationRequest& req, Invariant invariant);

bool BuildBeginOpMsg(const fuzz::BeginOperationRequest& proto_req,
                     keymaster::BeginOperationRequest& req);

bool BuildUpdateOpMsg(const fuzz::UpdateOperationRequest& proto_req,
                      keymaster::UpdateOperationRequest& req);

bool BuildFinishOpMsg(const fuzz::FinishOperationRequest& proto_req,
                      keymaster::FinishOperationRequest& req);
