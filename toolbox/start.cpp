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

#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include <android-base/properties.h>

using android::base::GetProperty;
using android::base::SetProperty;
using namespace std::literals;

static void ControlInit(const std::string& action, const std::string& target) {
    if (!android::base::SetProperty("ctl." + action, target)) {
        std::cerr << "Unable to " << action << " '" << target << "'\nSee dmesg for error reason."
                  << std::endl;
        exit(EXIT_FAILURE);
    }
}

static void ControlDefaultServices(bool start) {
    std::vector<std::string> services = {"netd", "surfaceflinger", "zygote"};

    // Only start zygote_secondary if not single arch.
    std::string zygote_configuration = GetProperty("ro.zygote", "");
    if (zygote_configuration != "zygote32" && zygote_configuration != "zygote64") {
        services.emplace_back("zygote_secondary");
    }

    if (start) {
        for (const auto& service : services) {
            ControlInit("start", service);
        }
    } else {
        for (auto it = services.crbegin(); it != services.crend(); ++it) {
            ControlInit("stop", *it);
        }
    }
}

static int StartStopMain(int argc, char** argv, bool start) {
    if (getuid()) {
        std::cerr << "Must be root" << std::endl;
        return EXIT_FAILURE;
    }

    if (argc == 1) {
        ControlDefaultServices(start);
    }

    std::string action = start ? "start" : "stop";

    if (argc == 2 && argv[1] == "--help"s) {
        std::cout << "usage: " << action
                  << " [SERVICE...]\n"
                     "\n"
                  << (start ? "Starts" : "Stops")
                  << " the given system service, or netd/surfaceflinger/zygotes." << std::endl;
        return EXIT_SUCCESS;
    }

    for (int i = 1; i < argc; ++i) {
        ControlInit(action, argv[i]);
    }
    return EXIT_SUCCESS;
}

extern "C" int start_main(int argc, char** argv) {
    return StartStopMain(argc, argv, true);
}

extern "C" int stop_main(int argc, char** argv) {
    return StartStopMain(argc, argv, false);
}

static int InterfaceMain(int argc, char** argv, bool start) {
    if (getuid()) {
        std::cerr << "Must be root" << std::endl;
        return EXIT_FAILURE;
    }

    std::string action = start ? "interface_start" : "interface_stop";

    if (argc == 1 || (argc == 2 && argv[1] == "--help"s)) {
        std::cout << "usage: " << action
                  << " [INTERFACE...]\n"
                     "\n"
                  << (start ? "Starts" : "Stops") << " the given interface." << std::endl;
        return EXIT_SUCCESS;
    }

    for (int i = 1; i < argc; ++i) {
        ControlInit(action, argv[i]);
    }
    return EXIT_SUCCESS;
}

extern "C" int interface_start_main(int argc, char** argv) {
    return InterfaceMain(argc, argv, true);
}

extern "C" int interface_stop_main(int argc, char** argv) {
    return InterfaceMain(argc, argv, false);
}