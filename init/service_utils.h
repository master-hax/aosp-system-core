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

#pragma once

#include <sys/resource.h>
#include <sys/types.h>

#include <string>
#include <vector>

#include "result.h"

namespace android {
namespace init {

Result<Success> EnterNamespace(int nstype, const char* path);

Result<Success> SetUpMountNamespace(bool remount_proc, bool remount_sys);

Result<Success> SetUpPidNamespace(const char* name);

struct ProcessAttributes {
    std::vector<std::pair<int, rlimit>> rlimits;
    bool create_proc_group;
    uid_t uid;
    gid_t gid;
    std::vector<gid_t> supp_gids;
    int priority;
};

Result<Success> SetProcessAttributes(const ProcessAttributes& attr);

Result<Success> WritePidToFiles(std::vector<std::string>* files);

}  // namespace init
}  // namespace android
