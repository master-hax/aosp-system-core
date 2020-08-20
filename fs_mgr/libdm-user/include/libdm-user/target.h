// Copyright (C) 2020 The Android Open Source Project
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

#include <string>
#include "channel.h"

namespace android {
namespace dm_user {

class target {
  public:
    // Represents an already-created target, which is referenced by UUID.
    target(std::string uuid) : uuid_(uuid) {}

    // Opens a new channel to the given target.
    channel open(void);

    // FIXME: Testing
    const auto& uuid(void) { return uuid_; }
    std::string control_path(void) { return std::string("/dev/dm-user-") + uuid(); }

  private:
    const std::string uuid_;
};

}  // namespace dm_user
}  // namespace android
