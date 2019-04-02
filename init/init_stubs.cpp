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

// first stage init do nothing init stub

#include "init.h"

#include <memory>
#include <string>
#include <vector>

#include "action_manager.h"
#include "action_parser.h"
#include "import_parser.h"
#include "service.h"

namespace android {
namespace init {

Parser CreateParser(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser;

    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, nullptr));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&action_manager, nullptr));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    return parser;
}

Parser CreateServiceOnlyParser(ServiceList& service_list) {
    Parser parser;

    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, nullptr));
    return parser;
}

std::vector<std::string> late_import_paths;

}  // namespace init
}  // namespace android
