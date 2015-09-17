/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "feature_set.h"

#include <string.h>

#include <algorithm>
#include <utility>
#include <vector>

#include <base/stringprintf.h>
#include <base/strings.h>

#include "adb_utils.h"

namespace {

// Feature format is <name1>__<version1>,<name2>__<version2>,etc.
constexpr char kVersionDelimiter[] = "__";
constexpr char kFeatureDelimiter = ',';

}  // namespace

FeatureSet::FeatureSet() {
}

FeatureSet::FeatureSet(FeaturesMap features) {
    features_map_.swap(features);
}

FeatureSet::FeatureSet(const std::string& features_string) {
    FromString(features_string);
}

std::string FeatureSet::ToString() const {
    std::vector<std::string> strings;

    for (const auto& pair : features_map_) {
        strings.push_back(android::base::StringPrintf(
                "%s%s%d", pair.first.c_str(), kVersionDelimiter, pair.second));
    }

    return android::base::Join(strings, kFeatureDelimiter);
}

void FeatureSet::FromString(const std::string& features) {
    features_map_.clear();

    for (const std::string& feature :
            android::base::Split(features, std::string(&kFeatureDelimiter, 1))) {
        // Default to version 1 if we can't find a version.
        StringPair parts = Partition(feature, kVersionDelimiter);
        features_map_[parts.first] = std::max(1, atoi(parts.second.c_str()));
    }
}

int FeatureSet::GetVersion(const std::string& feature_name) const {
    auto iter = features_map_.find(feature_name);
    if (iter == features_map_.end()) {
        return 0;
    }
    return iter->second;
}

int FeatureSet::GetSharedVersion(const std::string& feature_name) const {
    return std::min(GetVersion(feature_name),
                    supported_features().GetVersion(feature_name));
}

bool FeatureSet::CanUseShellProtocol() const {
    return GetSharedVersion(kFeatureShell) >= 2;
}

bool FeatureSet::CanUseShellTypeArgument() const {
    return GetSharedVersion(kFeatureShell) >= 3;
}

const FeatureSet& supported_features() {
    // Local static allocation to avoid global non-POD variables.
    static const FeatureSet* features = new FeatureSet({
        std::make_pair(kFeatureShell, 3)
    });

    return *features;
}

