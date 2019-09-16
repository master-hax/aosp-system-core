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

#pragma once

#include "adb_unique_fd.h"

#include "fastdeploy/proto/ApkEntry.pb.h"

#include <optional>
#include <string>

enum FastDeploy_AgentUpdateStrategy {
    FastDeploy_AgentUpdateAlways,
    FastDeploy_AgentUpdateNewerTimeStamp,
    FastDeploy_AgentUpdateDifferentVersion
};

void fastdeploy_set_local_agent(bool use_localagent);
int get_device_api_level();
void update_agent(FastDeploy_AgentUpdateStrategy agentUpdateStrategy);

std::string get_packagename_from_apk(const char* apkPath);
std::optional<com::android::fastdeploy::APKMetaData> extract_metadata(
        const std::string& packageName);
void create_patch(const char* apkPath, com::android::fastdeploy::APKMetaData metadata,
                  const char* patchPath);
void apply_patch_on_device(const std::string& packageName, const char* patchPath,
                           const char* outputPath);
void install_patch(const std::string& packageName, const char* patchPath, int argc,
                   const char** argv);
std::string get_patch_path(const std::string& packageName);
