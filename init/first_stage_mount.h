/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <fs_mgr.h>
#include <liblp/liblp.h>
#include <libsnapshot/snapshot.h>

#include "block_dev_initializer.h"
#include "result.h"

namespace android {
namespace init {

class FirstStageMount {
  public:
    virtual ~FirstStageMount() = default;

    // The factory method to create a FirstStageMount instance.
    static Result<std::unique_ptr<FirstStageMount>> Create();
    virtual bool
    DoCreateDevices() = 0;  // Creates devices and logical partitions from storage devices
    virtual bool DoFirstStageMount() = 0;  // Mounts fstab entries read from device tree.

  protected:
    FirstStageMount() = default;
};

void SetInitAvbVersionInRecovery();

}  // namespace init
}  // namespace android
