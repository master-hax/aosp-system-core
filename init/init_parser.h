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

#ifndef _INIT_INIT_PARSER_H_
#define _INIT_INIT_PARSER_H_

#include <map>
#include <string>
#include <vector>

#include <base/stringprintf.h>

class SectionParser {
public:
    virtual ~SectionParser() {
    }
    virtual bool ParseSection(const std::vector<std::string>& args,
                              std::string* err) = 0;
    virtual bool ParseLineSection(const std::vector<std::string>& args,
                                  const std::string& filename, int line,
                                  std::string* err) const = 0;
    virtual void EndSection() = 0;
    virtual void EndFile(const std::string& filename) = 0;
};

class Parser {
public:
    static Parser& GetInstance();
    void DumpState() const;
    bool ParseConfig(const std::string& path);
    void AddSectionParser(const std::string& name,
                          std::unique_ptr<SectionParser> parser);

private:
    Parser();

    void ParseData(const std::string& filename, const std::string& data);
    bool ParseConfigFile(const std::string& path);
    bool ParseConfigDir(const std::string& path);

    std::map<std::string, std::unique_ptr<SectionParser>> section_parsers_;
};

template <typename Function>
class KeywordMap {
public:
    using FunctionInfo = std::tuple<std::size_t, std::size_t, Function>;
    using Map = const std::map<std::string, FunctionInfo>;

    const Function FindFunction(const std::string& keyword,
                                size_t num_args,
                                std::string* err) const {
        using android::base::StringPrintf;

        auto function_info_it = map().find(keyword);
        if (function_info_it == map().end()) {
            *err = StringPrintf("invalid keyword '%s'", keyword.c_str());
            return nullptr;
        }

        auto function_info = function_info_it->second;

        auto min_args = std::get<0>(function_info);
        auto max_args = std::get<1>(function_info);
        if (min_args == max_args && num_args != min_args) {
            *err = StringPrintf("%s requires %zu argument%s",
                                keyword.c_str(), min_args,
                                (min_args > 1 || min_args == 0) ? "s" : "");
            return nullptr;
        }

        if (num_args < min_args || num_args > max_args) {
            if (max_args == std::numeric_limits<decltype(max_args)>::max()) {
                *err = StringPrintf("%s takes at least %zu argument%s",
                                    keyword.c_str(), min_args,
                                    min_args > 1 ? "s" : "");
            } else {
                *err = StringPrintf("%s takes between %zu and %zu arguments",
                                    keyword.c_str(), min_args, max_args);
            }
            return nullptr;
        }

        return std::get<Function>(function_info);
    }

    virtual ~KeywordMap() {
    }

private:
//Map of keyword ->
//(minimum number of arguments, maximum number of arguments, function pointer)
    virtual Map& map() const = 0;
};

#endif
