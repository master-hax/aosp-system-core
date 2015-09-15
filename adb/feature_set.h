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

#ifndef FEATURE_SET_H_
#define FEATURE_SET_H_

#include <string>
#include <unordered_map>

// A FeatureSet holds string feature names and associated version numbers. It
// also contains methods to convert to and from a string in order to serialize
// the data for passing between adb client, adb host, and adbd.
class FeatureSet {
  public:
    typedef std::unordered_map<std::string, int> FeaturesMap;

    FeatureSet();
    FeatureSet(FeaturesMap features);
    FeatureSet(const std::string& features_string);

    // Returns a feature version or 0 if it does not exist.
    int GetVersion(const std::string& feature_name) const;

    // Returns the highest feature version shared by both this FeatureSet and
    // the local supported_features() set.
    int GetSharedVersion(const std::string& feature_name) const;

    // Packs or unpacks a FeatureSet into a string for passing over a transport.
    std::string ToString() const;
    void FromString(const std::string& features_string);

    // Capability tests make it easier for each side to agree what each feature
    // enables without hardcoding version numbers.
    bool CanUseShellProtocol() const;

    // Access the underlying map directly. Useful for iterating over all
    // features and for unit testing.
    const FeaturesMap& features_map() const { return features_map_; }

  private:
    FeaturesMap features_map_;
};

// Returns the set of locally supported features.
const FeatureSet& supported_features();

// Only use alphanumeric and single underscores in feature names to avoid
// conflicts with banner or feature set parsing.
constexpr char kFeatureShell[] = "shell";

#endif  // FEATURE_SET_H_
