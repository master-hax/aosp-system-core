//
// Copyright (C) 2018 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <sys/wait.h>

#include <memory>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <selinux/selinux.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "builtins.h"
#include "import_parser.h"
#include "init.h"
#include "parser.h"
#include "property_service.h"
#include "selinux.h"
#include "service.h"
#include "sigchld_handler.h"

using android::base::FATAL;
using android::base::GetProperty;
using android::base::ScopedLogSeverity;
using android::base::SetProperty;

namespace android {
namespace init {

int RunInitServiceMain(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);

    if (argc != 2) {
        LOG(ERROR) << "Usage: " << argv[0] << " <init service to run>";
        return -1;
    }

    // We rely on the auto domain transitions from init -> service domain.
    if (setcon("u:r:init:s0") != 0) {
        LOG(ERROR) << "Failed to change context to init";
        return -1;
    }

    // Set up parsing and parse default scripts, similar to how init would.
    const BuiltinFunctionMap function_map;
    Action::set_function_map(&function_map);
    ActionManager& am = ActionManager::GetInstance();

    ServiceList& sl = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&sl, nullptr));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    {
        // Don't report parsing info or errors.
        ScopedLogSeverity scoped_log_severity(FATAL);
        parser.ParseConfig("/init.rc");
        parser.ParseConfig("/system/etc/init");
        parser.ParseConfig("/product/etc/init");
        parser.ParseConfig("/odm/etc/init");
        parser.ParseConfig("/vendor/etc/init");
    }

    // Initialize global state used by Service::Start()
    SelabelInitialize();

    std::string console = GetProperty("ro.boot.console", "");
    if (!console.empty()) {
        default_console = "/dev/" + console;
    }

    property_set = [](const std::string& name, const std::string& value) -> uint32_t {
        return SetProperty(name, value) ? 0 : -1;
    };

    // Find and launch the service.
    Service* service = ServiceList::GetInstance().FindService(argv[1]);
    if (!service) {
        LOG(ERROR) << "Could not find service '" << argv[1] << "'";
        return -1;
    }
    if (auto result = service->Start(); !result) {
        LOG(ERROR) << "Could not start service: " << result.error();
        return -1;
    }

    // Wait for service to exit without reaping.
    siginfo_t siginfo = {};
    TEMP_FAILURE_RETRY(waitid(P_ALL, 0, &siginfo, WEXITED | WNOWAIT));
    // Ensure that no onrestart actions get run.
    service->set_onrestart(Action{false, nullptr, "", 0, "", {}});
    // Reap the child as if init reaped it.
    ReapAnyOutstandingChildren();

    return 0;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    android::init::RunInitServiceMain(argc, argv);
}
