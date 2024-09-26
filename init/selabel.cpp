/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "selabel.h"

#include <selinux/android.h>

namespace android {
namespace init {

// A C++ wrapper around selabel_lookup() using the cached sehandle.
// If sehandle is null, this returns success with an empty context.
bool SelabelLookupFileContext(const std::string& key, int type, std::string* result) {
    result->clear();

    char* context;
    if (selabel_lookup(selinux_android_get_sehandle(), &context, key.c_str(), type) != 0) {
        return false;
    }
    *result = context;
    free(context);
    return true;
}

// A C++ wrapper around selabel_lookup_best_match() using the cached sehandle.
// If sehandle is null, this returns success with an empty context.
bool SelabelLookupFileContextBestMatch(const std::string& key,
                                       const std::vector<std::string>& aliases, int type,
                                       std::string* result) {
    result->clear();

    std::vector<const char*> c_aliases;
    for (const auto& alias : aliases) {
        c_aliases.emplace_back(alias.c_str());
    }
    c_aliases.emplace_back(nullptr);

    char* context;
    if (selabel_lookup_best_match(selinux_android_get_sehandle(), &context, key.c_str(),
                                  &c_aliases[0], type) != 0) {
        return false;
    }
    *result = context;
    free(context);
    return true;
}

}  // namespace init
}  // namespace android
