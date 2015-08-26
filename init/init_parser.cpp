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

#include "keywords.h"

#define KEYWORD(symbol, flags, nargs, func) \
    [ K_##symbol ] = { #symbol, func, nargs + 1, flags, },

static struct {
    const char *name;
    int (*func)(const std::vector<std::string>& args);
    size_t nargs;
    unsigned char flags;
} keyword_info[KEYWORD_COUNT] = {
    [ K_UNKNOWN ] = { "unknown", 0, 0, 0 },
#include "keywords.h"
};
#undef KEYWORD

BuiltinFunction kw_func(int kw) {
    return keyword_info[kw].func;
}

size_t kw_nargs(int kw) {
    return keyword_info[kw].nargs;
}

bool kw_is(int kw, char type) {
    return keyword_info[kw].flags & (type);
}

void Parser::DumpState() const {
    ServiceManager::GetInstance().DumpState();
    ActionManager::GetInstance().DumpState();
}

int lookup_keyword(const char *s)
{
    switch (*s++) {
    case 'b':
        if (!strcmp(s, "ootchart_init")) return K_bootchart_init;
        break;
    case 'c':
        if (!strcmp(s, "opy")) return K_copy;
        if (!strcmp(s, "lass")) return K_class;
        if (!strcmp(s, "lass_start")) return K_class_start;
        if (!strcmp(s, "lass_stop")) return K_class_stop;
        if (!strcmp(s, "lass_reset")) return K_class_reset;
        if (!strcmp(s, "onsole")) return K_console;
        if (!strcmp(s, "hown")) return K_chown;
        if (!strcmp(s, "hmod")) return K_chmod;
        if (!strcmp(s, "ritical")) return K_critical;
        break;
    case 'd':
        if (!strcmp(s, "isabled")) return K_disabled;
        if (!strcmp(s, "omainname")) return K_domainname;
        break;
    case 'e':
        if (!strcmp(s, "nable")) return K_enable;
        if (!strcmp(s, "xec")) return K_exec;
        if (!strcmp(s, "xport")) return K_export;
        break;
    case 'g':
        if (!strcmp(s, "roup")) return K_group;
        break;
    case 'h':
        if (!strcmp(s, "ostname")) return K_hostname;
        break;
    case 'i':
        if (!strcmp(s, "oprio")) return K_ioprio;
        if (!strcmp(s, "fup")) return K_ifup;
        if (!strcmp(s, "nsmod")) return K_insmod;
        if (!strcmp(s, "mport")) return K_import;
        if (!strcmp(s, "nstallkey")) return K_installkey;
        break;
    case 'k':
        if (!strcmp(s, "eycodes")) return K_keycodes;
        break;
    case 'l':
        if (!strcmp(s, "oglevel")) return K_loglevel;
        if (!strcmp(s, "oad_persist_props")) return K_load_persist_props;
        if (!strcmp(s, "oad_all_props")) return K_load_all_props;
        break;
    case 'm':
        if (!strcmp(s, "kdir")) return K_mkdir;
        if (!strcmp(s, "ount_all")) return K_mount_all;
        if (!strcmp(s, "ount")) return K_mount;
        break;
    case 'o':
        if (!strcmp(s, "n")) return K_on;
        if (!strcmp(s, "neshot")) return K_oneshot;
        if (!strcmp(s, "nrestart")) return K_onrestart;
        break;
    case 'p':
        if (!strcmp(s, "owerctl")) return K_powerctl;
        break;
    case 'r':
        if (!strcmp(s, "estart")) return K_restart;
        if (!strcmp(s, "estorecon")) return K_restorecon;
        if (!strcmp(s, "estorecon_recursive")) return K_restorecon_recursive;
        if (!strcmp(s, "mdir")) return K_rmdir;
        if (!strcmp(s, "m")) return K_rm;
        break;
    case 's':
        if (!strcmp(s, "eclabel")) return K_seclabel;
        if (!strcmp(s, "ervice")) return K_service;
        if (!strcmp(s, "etenv")) return K_setenv;
        if (!strcmp(s, "etprop")) return K_setprop;
        if (!strcmp(s, "etrlimit")) return K_setrlimit;
        if (!strcmp(s, "ocket")) return K_socket;
        if (!strcmp(s, "tart")) return K_start;
        if (!strcmp(s, "top")) return K_stop;
        if (!strcmp(s, "wapon_all")) return K_swapon_all;
        if (!strcmp(s, "ymlink")) return K_symlink;
        if (!strcmp(s, "ysclktz")) return K_sysclktz;
        break;
    case 't':
        if (!strcmp(s, "rigger")) return K_trigger;
        break;
    case 'u':
        if (!strcmp(s, "ser")) return K_user;
        break;
    case 'v':
        if (!strcmp(s, "erity_load_state")) return K_verity_load_state;
        if (!strcmp(s, "erity_update_state")) return K_verity_update_state;
        break;
    case 'w':
        if (!strcmp(s, "rite")) return K_write;
        if (!strcmp(s, "ritepid")) return K_writepid;
        if (!strcmp(s, "ait")) return K_wait;
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
