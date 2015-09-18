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

// Do not use any of [:;=,] in feature strings, they have special meaning
// in the connection banner.
const char kFeatureShell2[] = "shell_2";

const FeatureSet& supported_features() {
    // Local static allocation to avoid global non-POD variables.
    static const FeatureSet* features = new FeatureSet{
        kFeatureShell2
    };

    return *features;
}

