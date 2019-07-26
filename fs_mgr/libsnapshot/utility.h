// Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <functional>
#include <string>

#include <liblp/builder.h>

namespace android {
namespace snapshot {

enum class LoopDirective { BREAK, CONTINUE };

// Execute |func| on each partition in |builder| that ends with |suffix|.
// If |func| return CONTINUE, continue the loop. Otherwise, exit the loop
// and return false.
bool ForEachPartition(fs_mgr::MetadataBuilder* builder, const std::string& suffix,
                      const std::function<LoopDirective(fs_mgr::Partition*)>& func);

}  // namespace snapshot
}  // namespace android
