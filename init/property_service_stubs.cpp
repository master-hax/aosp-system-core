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

#include "property_service.h"

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_ 1
#include <sys/_system_properties.h>

namespace android {
namespace init {

bool CanReadProperty(const std::string& source_context, const std::string& name) {
    return false;
}

uint32_t SetProperty(const std::string& key, const std::string& value) {
    return PROP_ERROR_SET_FAILED;
}

uint32_t (*property_set)(const std::string& name, const std::string& value) = SetProperty;

uint32_t HandlePropertySet(const std::string&, const std::string&, const std::string&, const ucred&,
                           std::string*) {
    return PROP_ERROR_SET_FAILED;
}

}  // namespace init
}  // namespace android
