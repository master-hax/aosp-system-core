/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "init_parser.h"

#include <memory>
#include <vector>

#include "action_manager.h"
#include "action_parser.h"
#include "import_parser.h"
#include "parser.h"
#include "service.h"
#include "subcontext.h"

namespace android {
namespace init {

static std::vector<Subcontext>* subcontexts;

void InitSubcontexts() {
    subcontexts = InitializeSubcontexts();
}

Parser CreateParser(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser;

    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, subcontexts));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&action_manager, subcontexts));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    return parser;
}

// parser that only accepts new services
Parser CreateServiceOnlyParser(ServiceList& service_list) {
    Parser parser;

    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, subcontexts));

    return parser;
}

}  // namespace init
}  // namespace android
