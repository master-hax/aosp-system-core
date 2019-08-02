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

#include <map>
#include <set>
#include <string>

#include <hidl-util/FQName.h>

#include "result.h"

namespace android {
namespace init {

using InterfaceInheritanceHierarchyMap = std::map<android::FQName, std::set<android::FQName>>;

Result<InterfaceInheritanceHierarchyMap> ReadInterfaceInheritanceHierarchy(const std::string& path);

Result<void> CheckInterfaceInheritanceHierarchy(const std::set<std::string>& instances,
                                                const InterfaceInheritanceHierarchyMap& hierarchy);
Result<void> CheckInterfaceInheritanceHierarchy(const std::set<android::FQName>& interfaces,
                                                const InterfaceInheritanceHierarchyMap& hierarchy);

void SetKnownInterfaces(const InterfaceInheritanceHierarchyMap& hierarchy);

Result<void> IsKnownInterface(const std::string& intf);
Result<void> IsKnownInterface(const FQName& intf);

}  // namespace init
}  // namespace android
