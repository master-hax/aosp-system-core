// Copyright (C) 2015 The Android Open Source Project
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

#ifndef _INIT_PARSER_PARSER_H
#define _INIT_PARSER_PARSER_H

#include <map>
#include <string>
#include <vector>

namespace init {

class ParserSectionHandler {
 public:
  ParserSectionHandler() {}
  virtual ~ParserSectionHandler() {}

  // Is called when the Parser finds a new section.
  virtual void HandleSection(const std::vector<std::string>& args,
                             const void** priv) = 0;
  // Is called when the Parser finds a sub command to a section
  virtual void HandleSubCommand(const std::vector<std::string>& args,
                                const void* priv) = 0;
};

// Parses a file or string and will callback to an object that
// implements ParserSectionHandler to process sections.
class Parser {
 public:
  Parser();
  ~Parser();

  void AddSectionHandler(const std::string& name,
                         ParserSectionHandler* handler);
  bool ParseFile(const std::string& path);
  bool ParseData(const std::string& data);

 private:
  std::map<std::string, ParserSectionHandler*> handlers_;
  ParserSectionHandler* current_section_;
  const void* priv_;
};

}  // namespace init

#endif
