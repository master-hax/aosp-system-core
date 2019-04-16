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

#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <algorithm>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include <modprobe/modprobe.h>

std::string Modprobe::MakeCanonical(const std::string& module_path) {
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

bool Modprobe::ParseDepCallback(std::vector<std::string>&& args) {
    std::vector<std::string> deps;
    std::string prefix = "";

    // Set first item as our modules path
    std::string::size_type pos = args[0].find(':');
    if (args[0][0] != '/') {
        prefix = base_path + "/";
    }
    if (pos != std::string::npos) {
        deps.emplace_back(prefix + args[0].substr(0, pos));
    } else {
        LOG(FATAL) << "dependency lines must start with name followed by ':'";
    }

    // Remaining items are dependencies of our module
    for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
        if ((*arg)[0] != '/') {
            prefix = base_path + "/";
        } else {
            prefix = "";
        }
        deps.push_back(prefix + *arg);
    }

    this->module_deps_[MakeCanonical(args[0].substr(0, pos))] = deps;

    return true;
}

bool Modprobe::ParseAliasCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "alias") {
        LOG(FATAL) << "non-alias line encountered in modules.alias, found " << type;
    }

    if (args.size() != 3) {
        LOG(FATAL) << "alias lines in modules.alias must have 3 entries, not " << args.size();
    }

    std::string& alias = *it++;
    std::string& module_name = *it++;
    this->module_aliases_.emplace_back(alias, module_name);

    return true;
}

bool Modprobe::ParseSoftdepCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;
    std::string state = "";

    if (type != "softdep") {
        LOG(FATAL) << "non-softdep line encountered in modules.softdep, found " << type;
    }

    if (args.size() < 4) {
        LOG(FATAL) << "softdep lines in modules.softdep must have at least 4 entries";
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

    return true;
}

bool Modprobe::ParseLoadCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    std::string& module = *it++;

    this->module_load_.emplace_back(MakeCanonical(module));

    return true;
}

bool Modprobe::ParseOptionsCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;
    std::string& module = *it++;
    std::string options = "";

    module = MakeCanonical(module);

    if (type != "options") {
        LOG(FATAL) << "non-options line encountered in modules.options";
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
    return true;
}

std::string ReadFile(const std::string& path) {
    std::string content;
    android::base::unique_fd fd(
        TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        PLOG(ERROR) << "open() " << path << " failed";
        goto out;
    }

    // For security reasons, disallow world-writable or group-writable files.
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        PLOG(ERROR) << "fstat() failed";
        goto out;
    }
    if ((sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        PLOG(ERROR) << "Skipping insecure config file";
        goto out;
    }

    if (!android::base::ReadFdToString(fd, &content)) {
        PLOG(ERROR) << "Unable to read file contents";
        goto out;
    }

out:
    return content;
}

void Modprobe::ParseCfg(const std::string& cfg,
                        std::function<bool(std::vector<std::string>&&)> f) {
    std::string cfg_contents = ReadFile(cfg);
    if (cfg_contents.empty()) {
        return;
    }

    std::stringstream cfg_stream(cfg_contents);
    std::string line;
    while(std::getline(cfg_stream, line)) {
        std::stringstream line_stream(line);
        std::vector<std::string> args;
        std::string tok;
        while(std::getline(line_stream, tok, ' ')) {
            args.emplace_back(tok);
        }
        f(std::move(args));
    }
    return;
}

Modprobe::Modprobe(std::vector<std::string> base_paths) {
    using namespace std::placeholders;

    for (const auto& base_path : base_paths) {
        this->base_path = base_path;
        auto alias_callback = std::bind(&Modprobe::ParseAliasCallback, this, _1);
        ParseCfg(base_path + "/modules.alias", alias_callback);

        auto dep_callback = std::bind(&Modprobe::ParseDepCallback, this, _1);
        ParseCfg(base_path + "/modules.dep", dep_callback);

        auto softdep_callback = std::bind(&Modprobe::ParseSoftdepCallback, this, _1);
        ParseCfg(base_path + "/modules.softdep", softdep_callback);

        auto load_callback = std::bind(&Modprobe::ParseLoadCallback, this, _1);
        ParseCfg(base_path + "/modules.load", load_callback);

        auto options_callback = std::bind(&Modprobe::ParseOptionsCallback, this, _1);
        ParseCfg(base_path + "/modules.options", options_callback);
    }
}

std::vector<std::string> Modprobe::GetDependencies(const std::string& module) {
    auto it = module_deps_.find(module);
    if (it == module_deps_.end()) {
        return {};
    }
    return it->second;
}

bool Modprobe::InsmodWithDeps(const std::string& module_name) {
    if (module_name.empty()) {
        LOG(FATAL) << "Need valid module name, given: " << module_name;
    }

    auto dependencies = GetDependencies(module_name);
    if (dependencies.empty()) {
        LOG(ERROR) << "Module " << module_name << " not in dependency file";
        return false;
    }

    // load module dependencies in reverse order
    for (auto dep = dependencies.rbegin(); dep != dependencies.rend() - 1; ++dep) {
        if (!LoadWithAliases(MakeCanonical(*dep), true)) {
            return false;
        }
    }

    // try to load soft pre-dependencies
    for (const auto& [module, softdep] : module_pre_softdep_) {
        if (module_name == module) {
            LoadWithAliases(softdep, false);
        }
    }

    // load target module itself with args
    if (!Insmod(dependencies[0])) {
        return false;;
    }

    // try to load soft post-dependencies
    for (const auto& [module, softdep] : module_post_softdep_) {
        if (module_name == module) {
            LoadWithAliases(softdep, false);
        }
    }

    return true;
}

bool Modprobe::LoadWithAliases(const std::string& module_name, bool strict) {
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
        LOG(ERROR) << "LoadWithAliases did not find a module for " << module_name;
        return false;
    }
    return true;
}

bool Modprobe::LoadListedModules() {
    for (const auto& module : module_load_) {
        if (LoadWithAliases(module, true)) {
            return false;
        }
    }
    return true;
}

void Modprobe::HandleUevent(const std::string& modalias) {
    if (modalias.empty()) return;

    for (const auto& [alias, module] : module_aliases_) {
        if (fnmatch(alias.c_str(), modalias.c_str(), 0) != 0) continue;

        LOG(DEBUG) << "Loading kernel module '" << module << "' for alias '" << modalias
                   << "'";

        if (!InsmodWithDeps(module)) {
            LOG(ERROR) << "Cannot load module";
            continue;
        }

        return;
    }
}
