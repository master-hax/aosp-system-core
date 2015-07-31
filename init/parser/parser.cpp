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

#include "parser.h"

#include <string>
#include <vector>

#include "tokenizer.h"
#include "util.h"

namespace init {

Parser::Parser() : current_section_(nullptr), priv_(nullptr) {}

Parser::~Parser() {}

void Parser::AddSectionHandler(const std::string& name,
                               ParserSectionHandler* handler) {
  handlers_[name] = handler;
}

bool Parser::ParseFile(const std::string& path) {
  std::string data;
  if (!read_file(path.c_str(), &data)) {
    return false;
  }

  return ParseData(data);
}

bool Parser::ParseData(const std::string& data) {
  Tokenizer tokenizer(data);
  std::vector<std::string> args;

  if (handlers_.empty()) {
    return false;
  }

  while (tokenizer.Next()) {
    switch (tokenizer.current().type) {
      case Tokenizer::TOK_END:
        break;
      case Tokenizer::TOK_START:
        break;
      case Tokenizer::TOK_TEXT:
        args.push_back(tokenizer.current().text);
        break;
      case Tokenizer::TOK_NEWLINE:
        if (args.empty())
          break;

        if (handlers_.count(args[0])) {
          current_section_ = handlers_[args[0]];
          current_section_->HandleSection(args, &priv_);
        } else {
          if (current_section_) {
            current_section_->HandleSubCommand(args, priv_);
          }
        }
        args.clear();
        break;
    }
  }
  return true;
}

}  // namespace init