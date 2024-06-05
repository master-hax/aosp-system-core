/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <algorithm>
#include <string>

namespace util {

unsigned int GetCgroupDepth(const std::string& controller_root, const std::string& path) {
    if (controller_root.empty() || path.empty() || !path.starts_with(controller_root)) return 0;

    int depth = std::count(path.begin() + controller_root.size(), path.end(), '/');
    if (path.back() == '/') --depth;

    return depth;
}

}  // namespace util
