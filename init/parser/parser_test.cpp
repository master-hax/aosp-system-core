/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "parser.h"

#include <errno.h>
#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>

namespace init {

class TestHandler : public ParserSectionHandler {
 public:
  TestHandler() {
    section_called = 0;
    subcommand_called = 0;
  }
  void HandleSection(const std::vector<std::string>& args, const void** priv) {
    section_called++;
    last_args = args;
    *priv = this;
  }
  void HandleSubCommand(const std::vector<std::string>& args,
                        const void* priv) {
    subcommand_called++;
    last_args = args;
    last_priv = priv;
  }

  int section_called;
  int subcommand_called;
  std::vector<std::string> last_args;
  const void* last_priv;
};

TEST(parser, NoHandlers) {
  Parser parser;
  ASSERT_FALSE(parser.ParseData("Testing\n"));
}

TEST(parser, NoSections) {
  Parser parser;
  TestHandler handler;
  parser.AddSectionHandler("service", &handler);
  ASSERT_TRUE(parser.ParseData("bad data\n"));
  ASSERT_EQ(0, handler.section_called);
  ASSERT_EQ(0, handler.subcommand_called);
  ASSERT_TRUE(handler.last_args.empty());
}

TEST(parser, SingleSections) {
  Parser parser;
  TestHandler handler;
  parser.AddSectionHandler("service", &handler);
  ASSERT_TRUE(parser.ParseData("service test\n"));
  ASSERT_EQ(1, handler.section_called);
  ASSERT_EQ(0, handler.subcommand_called);
  ASSERT_EQ(2UL, handler.last_args.size());
  ASSERT_EQ("service", handler.last_args[0]);
  ASSERT_EQ("test", handler.last_args[1]);
}

TEST(parser, TwoSections) {
  Parser parser;
  TestHandler handler;
  parser.AddSectionHandler("service", &handler);
  ASSERT_TRUE(parser.ParseData("service test\nservice test2\n"));
  ASSERT_EQ(2, handler.section_called);
  ASSERT_EQ(0, handler.subcommand_called);
  ASSERT_EQ(2UL, handler.last_args.size());
  ASSERT_EQ("service", handler.last_args[0]);
  ASSERT_EQ("test2", handler.last_args[1]);
}

TEST(parser, ThreeSections) {
  Parser parser;
  TestHandler handler;
  parser.AddSectionHandler("service", &handler);
  ASSERT_TRUE(parser.ParseData("service test\nservice test2\nservice test3\n"));
  ASSERT_EQ(3, handler.section_called);
  ASSERT_EQ(0, handler.subcommand_called);
  ASSERT_EQ(2UL, handler.last_args.size());
  ASSERT_EQ("service", handler.last_args[0]);
  ASSERT_EQ("test3", handler.last_args[1]);
}

TEST(parser, SectionsWithCommand) {
  Parser parser;
  TestHandler handler;
  parser.AddSectionHandler("service", &handler);
  ASSERT_TRUE(parser.ParseData("service test\n\tfoo bar\n"));
  ASSERT_EQ(1, handler.section_called);
  ASSERT_EQ(1, handler.subcommand_called);
  ASSERT_EQ(2UL, handler.last_args.size());
  ASSERT_EQ("foo", handler.last_args[0]);
  ASSERT_EQ("bar", handler.last_args[1]);
  ASSERT_EQ(handler.last_priv, &handler);
}

}  // namespace init
