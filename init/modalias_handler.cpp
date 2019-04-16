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
#include <sys/stat.h>
#include <sys/syscall.h>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "parser.h"
#include "util.h"

namespace android {
namespace init {

std::string ModaliasHandler::MakeCanonical(const std::string& module_path) {
    auto start = module_path.find_last_of('/');
    if (start == std::string::npos) {
        start = 0;
    } else {
        start += 1;
    }
    auto end = module_path.size();
    if (android::base::EndsWith(module_path, ".ko")) {
        end -= 3;
    }
    if ((end - start) <= 1) {
        LOG(FATAL) << "malformed module name: " << module_path;
    }
    std::string module_name = module_path.substr(start, end  - start);
    // module names can have '-', but their file names will have '_'
    std::replace(module_name.begin(), module_name.end(), '-', '_');
    return module_name;
}

Result<Success> ModaliasHandler::ParseDepCallback(std::vector<std::string>&& args) {
    std::vector<std::string> deps;

    // Set first item as our modules path
    std::string::size_type pos = args[0].find(':');
    if (pos != std::string::npos) {
        deps.emplace_back(base_path + args[0].substr(0, pos));
    } else {
        return Error() << "dependency lines must start with name followed by ':'";
    }

    // Remaining items are dependencies of our module
    for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
        deps.push_back(base_path + *arg);
    }

    this->module_deps_[MakeCanonical(args[0].substr(0, pos))] = deps;

    return Success();
}

Result<Success> ModaliasHandler::ParseAliasCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "alias") {
        return Error() << "we only handle alias lines, got: " << type;
    }

    if (args.size() != 3) {
        return Error() << "alias lines must have 3 entries";
    }

    std::string& alias = *it++;
    std::string& module_name = *it++;
    this->module_aliases_.emplace_back(alias, module_name);

    return Success();
}

Result<Success> ModaliasHandler::ParseSoftdepCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;
    std::string state = "";

    if (type != "softdep") {
        return Error() << "we only handle softdep lines, got: " << type;
    }

    if (args.size() < 4) {
        return Error() << "softdep lines must have at least 4 entries";
    }

    std::string& module = *it++;
    while (it != args.end()) {
        const std::string& token = *it++;
        if (token == "pre:" || token == "post:") {
            state = token;
            continue;
        }
        if (state == "") {
            LOG(FATAL) << "malformed modules.softdep at token " << token;
        }
        if (state == "pre:") {
            this->module_pre_softdep_.emplace_back(module, token);
        } else {
            this->module_post_softdep_.emplace_back(module, token);
        }
    }

    return Success();
}

Result<Success> ModaliasHandler::ParseLoadCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    std::string& module = *it++;

    this->module_load_.emplace_back(MakeCanonical(module));

    return Success();
}

Result<Success> ModaliasHandler::ParseOptionsCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;
    std::string& module = *it++;
    std::string options = "";

    module = MakeCanonical(module);

    if (type != "options") {
        return Error() << "we only handle options lines, got: " << type;
    }

    while (it != args.end()) {
        options += *it++;
        if (it != args.end()) {
            options += " ";
        }
    }

    auto [unused, inserted] = this->module_options_.emplace(module, options);
    if (!inserted) {
        LOG(FATAL) << "multiple options lines present for module " << module;
    }
    return Success();
}

ModaliasHandler::ModaliasHandler(std::vector<std::string> base_paths) {
    using namespace std::placeholders;

    Parser alias_parser;
    auto alias_callback = std::bind(&ModaliasHandler::ParseAliasCallback, this, _1);
    alias_parser.AddSingleLineParser("alias", alias_callback);
    for (const auto& base_path : base_paths) {
        alias_parser.ParseConfig(base_path + "modules.alias");
    }

    Parser dep_parser;
    auto dep_callback = std::bind(&ModaliasHandler::ParseDepCallback, this, _1);
    dep_parser.AddSingleLineParser("", dep_callback);
    for (const auto& base_path : base_paths) {
        this->base_path = base_path;
        dep_parser.ParseConfig(base_path + "modules.dep");
    }

    Parser softdep_parser;
    auto softdep_callback = std::bind(&ModaliasHandler::ParseSoftdepCallback, this, _1);
    softdep_parser.AddSingleLineParser("softdep", softdep_callback);
    for (const auto& base_path : base_paths) {
        softdep_parser.ParseConfig(base_path + "modules.softdep");
    }

    Parser load_parser;
    auto load_callback = std::bind(&ModaliasHandler::ParseLoadCallback, this, _1);
    load_parser.AddSingleLineParser("", load_callback);
    for (const auto& base_path : base_paths) {
        load_parser.ParseConfig(base_path + "modules.load");
    }

    Parser options_parser;
    auto options_callback = std::bind(&ModaliasHandler::ParseOptionsCallback, this, _1);
    options_parser.AddSingleLineParser("options", options_callback);
    for (const auto& base_path : base_paths) {
        options_parser.ParseConfig(base_path + "modules.options");
    }
}

Result<Success> ModaliasHandler::Insmod(const std::string& path_name) {
    base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(path_name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        return ErrnoError() << "Could not open module '" << path_name << "'";
    }

    std::string options = "";
    auto options_iter = module_options_.find(MakeCanonical(path_name));
    if (options_iter != module_options_.end()) {
        options = options_iter->second;
    }

    LOG(INFO) << "Loading module " << path_name << " with args \"" << options << "\"";
    int ret = syscall(__NR_finit_module, fd.get(), options.c_str(), 0);
    if (ret != 0) {
        if (errno == EEXIST) {
            // Module already loaded
            LOG(INFO) << "Module already loaded";
            return Success();
        }
        return ErrnoError() << "Failed to insmod '" << path_name << "' with args '" << options << "'";
    }

    LOG(INFO) << "Loaded kernel module " << path_name;
    return Success();
}

std::vector<std::string> ModaliasHandler::GetDependencies(const std::string& module) {
    auto it = module_deps_.find(module);
    if (it == module_deps_.end()) {
        return {};
    }
    return it->second;
}

Result<Success> ModaliasHandler::InsmodWithDeps(const std::string& module_name) {
    if (module_name.empty()) {
        return Error() << "Need valid module name";
    }

    auto dependencies = GetDependencies(module_name);
    if (dependencies.empty()) {
        return Error() << "Module not in dependency file";
    }

    // load module dependencies in reverse order
    for (auto dep = dependencies.rbegin(); dep != dependencies.rend() - 1; ++dep) {
        if (auto result = Insmod(*dep); !result) {
            return result;
        }
    }

    // try to load soft pre-dependencies
    for (const auto& [module, softdep] : module_pre_softdep_) {
        if (module_name == module) {
            LoadWithAliases(softdep, false);
        }
    }

    // load target module itself with args
    if (auto result = Insmod(dependencies[0]); !result) {
        return result;
    }

    // try to load soft post-dependencies
    for (const auto& [module, softdep] : module_post_softdep_) {
        if (module_name == module) {
            LoadWithAliases(softdep, false);
        }
    }

    return Success();
}

bool ModaliasHandler::ModuleExists(const std::string& module_name) {
    struct stat fileStat;
    auto deps = GetDependencies(module_name);
    if (deps.empty()) {
        // missing deps can happen in the case of an alias
        return false;
    }
    if (stat(deps.front().c_str(), &fileStat)) {
        return false;
    }
    if (!S_ISREG(fileStat.st_mode)) {
        return false;
    }
    return true;
}

void ModaliasHandler::LoadWithAliases(const std::string& module_name,
                                      bool strict) {
    std::vector<std::string> modules_to_load = { module_name };
    bool module_loaded = false;

    // use aliases to expand list of modules to load (multiple modules
    // may alias themselves to the requested name)
    for (const auto& [alias, aliased_module] : module_aliases_) {
        if (fnmatch(alias.c_str(), module_name.c_str(), 0) != 0) continue;
        modules_to_load.emplace_back(aliased_module);
    }

    // attempt to load all modules aliased to this name
    for (const auto& module : modules_to_load) {
        if (!ModuleExists(module)) {
            continue;
        }
        if (InsmodWithDeps(module)) {
            module_loaded = true;
        }
    }

    if (strict && !module_loaded) {
        LOG(FATAL) << "LoadWithAliases did not find a module for " << module_name;
    }
}

void ModaliasHandler::LoadListedModules() {
    for (const auto& module : module_load_) {
        LoadWithAliases(module, true);
    }
}

void ModaliasHandler::HandleUevent(const Uevent& uevent) {
    if (uevent.modalias.empty()) return;

    for (const auto& [alias, module] : module_aliases_) {
        if (fnmatch(alias.c_str(), uevent.modalias.c_str(), 0) != 0) continue;  // Keep looking

        LOG(DEBUG) << "Loading kernel module '" << module << "' for alias '" << uevent.modalias
                   << "'";

        if (auto result = InsmodWithDeps(module); !result) {
            LOG(ERROR) << "Cannot load module: " << result.error();
            // try another one since there may be another match
            continue;
        }

        // loading was successful
        return;
    }
}

}  // namespace init
}  // namespace android
