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

#include <string>
#include <vector>

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
};

#define SECTION 0x01
#define COMMAND 0x02
#define OPTION  0x04

using BuiltinFunction = int (*) (const std::vector<std::string>& args);

int lookup_keyword(const char *s);
BuiltinFunction kw_func(int kw);
size_t kw_nargs(int kw);
bool kw_is(int kw, char type);

class Action;

bool init_parse_config(const char* path);
int expand_props(const std::string& src, std::string* dst);

#endif
