//
// Copyright (C) 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef PROPERTY_CONTEXT_SERIALIZER_H
#define PROPERTY_CONTEXT_SERIALIZER_H

#include <string>
#include <vector>

#include <android-base/result.h>

namespace android {
namespace properties {

Result<std::string> BuildTrie(
    const std::vector<std::pair<std::string, std::string>>& prefixes_with_context,
    const std::vector<std::pair<std::string, std::string>>& exact_matches_with_context,
    const std::string& default_context);

}  // namespace properties
}  // namespace android

#endif
