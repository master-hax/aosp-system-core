/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "modalias_handler.h"

#include <fnmatch.h>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>

#include "parser.h"
#include "util.h"

extern "C" {
extern int init_module(void* module_image, unsigned long len, const char* param_values);
}

namespace android {
namespace init {

Result<Success> ModaliasHandler::parseDepCallback(std::vector<std::string>&& args) {
    std::vector<std::string> deps;

    // Set first item as our modules path
    std::string::size_type pos = args[0].find(':');
    if (pos != std::string::npos) {
        deps.emplace_back(args[0].substr(0, pos));
    } else {
        return Error() << "dependency lines must start with name followed by ':'";
    }

    // Remaining items are dependencies of our module
    for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
        deps.push_back(*arg);
    }

    // Key is striped module name to match names in alias file
    std::size_t start = args[0].find_last_of("/");
    std::size_t end = args[0].find(".ko:");
    auto mod_name = args[0].substr(start + 1, (end - start) - 1);
    std::replace(mod_name.begin(), mod_name.end(), '-', '_');
    this->module_deps[mod_name] = deps;

    return Success();
}

Result<Success> ModaliasHandler::parseAliasCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != (std::string) "alias") {
        // we only handle alias lines, skip others
        return Error();
    }

    if (args.size() != 3) {
        return Error() << "alias lines must have 3 entries";
    }

    std::string& alias = *it++;
    std::string& module_name = *it++;
    this->module_aliases.emplace_back(alias, module_name);

    return Success();
}

ModaliasHandler::ModaliasHandler() {
    using namespace std::placeholders;

    static const std::string base_path = "/vendor/lib/modules/";

    Parser aliasParser;
    auto aliasCallback = std::bind(&ModaliasHandler::parseAliasCallback, this, _1);
    aliasParser.AddSingleLineParser("alias", aliasCallback);
    aliasParser.ParseConfig(base_path + "modules.alias");

    Parser depParser;
    auto depCallback = std::bind(&ModaliasHandler::parseDepCallback, this, _1);
    depParser.AddSingleLineParser("", depCallback);
    depParser.ParseConfig(base_path + "modules.dep");
}

int ModaliasHandler::insmod(std::string path_name, std::string args) {
    auto module_data_result = ReadFile(path_name);
    if (!module_data_result) {
        LOG(ERROR) << "Couldn't load module '" << path_name << "': " << module_data_result.error();
        return -1;
    }
    auto module_data = module_data_result.value();

    int ret = init_module((void*)module_data.data(), module_data.length(), args.data());
    if (ret != 0) {
        if (errno == EEXIST) {
            // Module already loaded
            return 0;
        }
        PLOG(ERROR) << "Failed to insmod '" << path_name << "' with args '" << args << "'";
        return ret;
    }

    LOG(INFO) << "Loaded kernel module " << path_name;
    return 0;
}

int ModaliasHandler::insmodWithDeps(std::string module_name, std::string args) {
    if (module_name.empty()) {
        LOG(ERROR) << "Need valid module name";
        return -1;
    }

    if (module_deps.count(module_name) < 1) {
        LOG(ERROR) << "Module '" << module_name << "' not in dependency file";
        return -1;  // module not in dependency file
    }

    auto dependencies = module_deps[module_name];
    // load module dependencies in reverse order
    for (auto dep = dependencies.rbegin(); dep != dependencies.rend() - 1; ++dep) {
        int ret = insmod(*dep, "");
        if (ret) return ret;
    }

    // load target module itself with args
    return insmod(dependencies[0], args);
}

void ModaliasHandler::HandleModaliasEvent(const Uevent& uevent) {
    if (uevent.modalias.empty()) return;

    for (auto alias : module_aliases) {
        if (fnmatch(alias.first.c_str(), uevent.modalias.c_str(), 0) != 0)
            continue;  // Keep looking

        LOG(DEBUG) << "Loading kernel module '" << alias.second << "' for alias '"
                   << uevent.modalias << "'";

        if (insmodWithDeps(alias.second, "")) {
            LOG(ERROR) << "Cannot load module " << alias.second;
            // try another one since there may be another match
            continue;
        }

        // loading was successful
        return;
    }
}

}  // namespace init
}  // namespace android
