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

#include <gtest/gtest.h>

#include <cctype>
#include <utility>

TEST(FeatureSet, GetVersion) {
    FeatureSet features({std::make_pair("foo", 3),
                         std::make_pair("bar", 52),
                         std::make_pair("baz", 1)});

    ASSERT_EQ(3U, features.features_map().size());
    ASSERT_EQ(3, features.GetVersion("foo"));
    ASSERT_EQ(52, features.GetVersion("bar"));
    ASSERT_EQ(1, features.GetVersion("baz"));
    ASSERT_EQ(0, features.GetVersion("not_a_feature"));
}

TEST(FeatureSet, GetSharedVersion) {
    // Get the supported shell version.
    int version = supported_features().GetVersion(kFeatureShell);
    ASSERT_TRUE(version > 0);

    // Higher version should share the lower version.
    FeatureSet higher_set({std::make_pair(kFeatureShell, version + 1)});
    ASSERT_EQ(version, higher_set.GetSharedVersion(kFeatureShell));

    // Lower version should share itself.
    FeatureSet lower_set({std::make_pair(kFeatureShell, version - 1)});
    ASSERT_EQ(version - 1, lower_set.GetSharedVersion(kFeatureShell));

    // Non-existent feature should share version 0.
    FeatureSet empty_set;
    ASSERT_EQ(0, empty_set.GetSharedVersion(kFeatureShell));
}

TEST(FeatureSet, ToAndFromString) {
    FeatureSet features({std::make_pair("foo", 3),
                         std::make_pair("bar", 52),
                         std::make_pair("baz", 1)});
    FeatureSet features2;

    features2.FromString(features.ToString());
    ASSERT_EQ(features.features_map(), features2.features_map());

    // Make sure all the supported features can be passed as a string.
    features2.FromString(supported_features().ToString());
    ASSERT_EQ(supported_features().features_map(), features2.features_map());
}

// Verifies that all supported feature names are legal.
TEST(FeatureSet, LegalSupportedFeaturesNames) {
    for (const auto& feature : supported_features().features_map()) {
        for (char c : feature.first) {
            EXPECT_TRUE(isalnum(c) || c == '_');
        }
    }
}
