/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "context_list.h"

#include <android-base/strings.h>

#include "init_context.h"

using android::base::StartsWith;

namespace android {
namespace init {

const std::string kVendorContext = "u:r:vendor_init:s0";

void ContextList::Initialize() {
    init_context_.reset(new InitContext());
}

ContextInterface* ContextList::GetContext(const std::string& path) {
    ContextInterface* result = init_context_.get();
    for (auto& context : contexts_) {
        if (StartsWith(path, context->path_prefix())) {
            result = context.get();
            break;
        }
    }
    return result;
}

bool ContextList::ReapChild(pid_t pid) {
    for (auto& context : contexts_) {
        if (context->pid() == pid) {
            context->Restart();
            return true;
        }
    }
    return false;
}

}  // namespace init
}  // namespace android
