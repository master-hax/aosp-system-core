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

#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>

#include <modprobe/modprobe.h>
#include <iostream>

static void print_usage(void) {
    std::cerr << "Usage:" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  modprobe [-alrqvsDb] [-d DIR] [MODULE]+" << std::endl;
    std::cerr << "  modprobe [-alrqvsDb] [-d DIR] MODULE [symbol=value][...]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  -d: Load modules from DIR, option may be used multiple times" << std::endl;
    std::cerr << "  -r: Remove MODULE (multiple modules may be specified)" << std::endl;
    std::cerr << "  -q: Quiet" << std::endl;
    std::cerr << "  -v: Verbose" << std::endl;
    std::cerr << std::endl;
}

extern "C" int modprobe_main(int argc, char** argv) {
    std::vector<std::string> modules;
    std::vector<std::string> module_parameters;
    std::vector<std::string> mod_dirs;
    bool removeModules = false;
    bool verbose = false;
    int rv = EXIT_SUCCESS;

    int opt;
    while ((opt = getopt(argc, argv, "ard:qv")) != -1) {
        switch (opt) {
            case 'a':
                // toybox modprobe supported -a to load multiple modules, this
                // is supported here by default, ignore flag
                break;
            case 'r':
                removeModules = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'q':
                verbose = false;
                break;
            case 'd':
                mod_dirs.emplace_back(optarg);
                break;
            default:
                std::cerr << "Unrecognized option: " << opt << std::endl;
                return EXIT_FAILURE;
        }
    }

    for (opt = optind; opt < argc; opt++) {
        if (!strchr(argv[opt], '=')) {
            modules.emplace_back(argv[opt]);
        } else {
            module_parameters.emplace_back(argv[opt]);
        }
    }

    if (verbose) {
        std::cout << "removeModules is " << removeModules << std::endl;
        std::cout << "verbose is " << verbose << std::endl;
        std::cout << "mod_dirs is: ";
        for (auto i = mod_dirs.begin(); i != mod_dirs.end(); i++) std::cout << *i << " ";
        std::cout << std::endl;
        std::cout << "modules is: ";
        for (auto i = modules.begin(); i != modules.end(); i++) std::cout << *i << " ";
        std::cout << std::endl;
        std::cout << "module parameters is: ";
        for (auto i = module_parameters.begin(); i != module_parameters.end(); i++)
            std::cout << *i << " ";
        std::cout << std::endl;
    }

    if (modules.empty()) {
        std::cerr << "No modules given." << std::endl;
        print_usage();
        return EXIT_FAILURE;
    }
    if (mod_dirs.empty()) {
        std::cerr << "No module configuration directories given." << std::endl;
        print_usage();
        return EXIT_FAILURE;
    }
    if (module_parameters.size() > 1 && modules.size() > 1) {
        std::cerr << "Only one module may be loaded when specying module parameters." << std::endl;
        print_usage();
        return EXIT_FAILURE;
    }

    Modprobe m(mod_dirs);

    for (auto module = modules.begin(); module != modules.end(); module++) {
        if (!removeModules) {
            if (!m.LoadWithAliases(*module, true)) {
                std::cerr << "Failed to load module " << *module;
                rv = EXIT_FAILURE;
            }
        } else {
            if (m.Remove(*module)) {
                std::cerr << "Failed to remove module " << *module;
                rv = EXIT_FAILURE;
            }
        }
    }

    return rv;
}
