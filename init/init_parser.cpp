/*
 * Copyright (C) 2010 The Android Open Source Project
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "action.h"
#include "init.h"
#include "init_parser.h"
#include "log.h"
#include "parser.h"
#include "service.h"
#include "util.h"

#include <base/stringprintf.h>
#include <cutils/iosched_policy.h>
#include <cutils/list.h>

void Parser::DumpState() const {
    ServiceManager::GetInstance().DumpState();
    ActionManager::GetInstance().DumpState();
}

#include "keywords.h"
int lookup_keyword(const char *s)
{

    switch (*s++) {
    case 'c':
        if (!strcmp(s, "lass")) return K_class;
        if (!strcmp(s, "onsole")) return K_console;
        if (!strcmp(s, "ritical")) return K_critical;
        break;
    case 'd':
        if (!strcmp(s, "isabled")) return K_disabled;
        break;
    case 'g':
        if (!strcmp(s, "roup")) return K_group;
        break;
    case 'i':
        if (!strcmp(s, "oprio")) return K_ioprio;
        break;
    case 'k':
        if (!strcmp(s, "eycodes")) return K_keycodes;
        break;
    case 'o':
        if (!strcmp(s, "neshot")) return K_oneshot;
        if (!strcmp(s, "nrestart")) return K_onrestart;
        break;
    case 's':
        if (!strcmp(s, "eclabel")) return K_seclabel;
        if (!strcmp(s, "etenv")) return K_setenv;
        if (!strcmp(s, "ocket")) return K_socket;
        break;
    case 'u':
        if (!strcmp(s, "ser")) return K_user;
        break;
    case 'w':
        if (!strcmp(s, "ritepid")) return K_writepid;
        break;
    }
    return K_UNKNOWN;

}

class ImportParser : public SectionParser {
public:
    ImportParser(std::vector<std::string>* imports) : imports_(imports) {
    }
    bool ParseSection(const std::vector<std::string>& args,
                      std::string* err) override;
    bool ParseLineSection(const std::vector<std::string>& args,
                          const std::string& filename, int line,
                          std::string* err) const override {
        return true;
    }
    void EndSection() override {
    }
private:
    std::vector<std::string>* imports_;
};

bool ImportParser::ParseSection(const std::vector<std::string>& args,
                                std::string* err) {
    if (args.size() != 2) {
        *err = "single argument needed for import\n";
        return false;
    }

    std::string conf_file;
    int ret = expand_props(args[1], &conf_file);
    if (ret) {
        *err = "error while expanding import";
        return false;
    }

    INFO("Added '%s' to import list\n", conf_file.c_str());
    imports_->emplace_back(std::move(conf_file));
    return true;
}

Parser::Parser() {
    AddSectionParser("import", std::make_unique<ImportParser>(&imports_));
}

Parser& Parser::GetInstance() {
    static Parser instance;
    return instance;
}

void Parser::AddSectionParser(const std::string& name,
                              std::unique_ptr<SectionParser> parser) {
    section_parsers_[name] = std::move(parser);
}

void Parser::ParseData(const std::string& filename, const std::string& data)
{
    //TODO: Use a parser with const input and remove this copy
    std::vector<char> data_copy(data.begin(), data.end());
    data_copy.push_back('\0');

    parse_state state;
    state.filename = filename.c_str();
    state.line = 0;
    state.ptr = &data_copy[0];
    state.nexttoken = 0;

    SectionParser* section_parser = nullptr;
    std::vector<std::string> args;

    for (;;) {
        switch (next_token(&state)) {
        case T_EOF:
            if (section_parser) {
                section_parser->EndSection();
            }
            return;
        case T_NEWLINE:
            state.line++;
            if (args.empty()) {
                break;
            }
            if (section_parsers_.count(args[0])) {
                if (section_parser) {
                    section_parser->EndSection();
                }
                section_parser = section_parsers_[args[0]].get();
                std::string ret_err;
                if (!section_parser->ParseSection(args, &ret_err)) {
                    parse_error(&state, "%s\n", ret_err.c_str());
                    section_parser = nullptr;
                }
            } else if (section_parser) {
                std::string ret_err;
                if (!section_parser->ParseLineSection(args, state.filename,
                                                      state.line, &ret_err)) {
                    parse_error(&state, "%s\n", ret_err.c_str());
                }
            }
            args.clear();
            break;
        case T_TEXT:
            args.emplace_back(state.text);
            break;
        }
    }
}

void Parser::HandleImports(const std::string& filename) {
    auto current_imports = std::move(imports_);
    imports_.clear();
    for (const auto& s : current_imports) {
        if (!ParseConfig(s)) {
            ERROR("could not import file '%s' from '%s': %s\n",
                  s.c_str(), filename.c_str(), strerror(errno));
        }
    }
}

bool Parser::ParseConfigFile(const std::string& path) {
    INFO("Parsing file %s...\n", path.c_str());
    Timer t;
    std::string data;
    if (!read_file(path.c_str(), &data)) {
        return false;
    }

    data.push_back('\n'); // TODO: fix parse_config.
    ParseData(path, data);
    HandleImports(path);
    DumpState();

    NOTICE("(Parsing %s took %.2fs.)\n", path.c_str(), t.duration());
    return true;
}

bool Parser::ParseConfigDir(const std::string& path) {
    INFO("Parsing directory %s...\n", path.c_str());
    std::unique_ptr<DIR, int(*)(DIR*)> config_dir(opendir(path.c_str()), closedir);
    if (!config_dir) {
        ERROR("Could not import directory '%s'\n", path.c_str());
        return false;
    }
    dirent* current_file;
    while ((current_file = readdir(config_dir.get()))) {
        std::string current_path =
            android::base::StringPrintf("%s/%s", path.c_str(), current_file->d_name);
        // Ignore directories and only process regular files.
        if (current_file->d_type == DT_REG) {
            if (!ParseConfigFile(current_path)) {
                ERROR("could not import file '%s'\n", current_path.c_str());
            }
        }
    }
    return true;
}

bool Parser::ParseConfig(const std::string& path) {
    if (is_dir(path.c_str())) {
        return ParseConfigDir(path);
    }
    return ParseConfigFile(path);
}
