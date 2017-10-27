//
// Copyright (C) 2017 The Android Open Source Project
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
//

#include "trie_builder.h"

#include <gtest/gtest.h>

namespace android {
namespace properties {

TEST(propertycontextserializer, BuildTrie_Simple) {
  TrieBuilderNode builder_root("root");
  std::set<std::string> contexts;

  // Set up root node
  contexts.emplace("default");
  builder_root.set_context(&(*contexts.find("default")));

  // Add test data to tree
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "test.", "1st", false));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "test.test", "2nd", false));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "test.test1", "3rd", true));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "test.test2", "3rd", true));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "test.test3", "3rd", true));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "this.is.a.long.string", "4th", true));

  ASSERT_EQ(5U, contexts.size());

  // Check the root node
  EXPECT_EQ("root", builder_root.name());
  ASSERT_NE(nullptr, builder_root.context());
  EXPECT_EQ("default", *builder_root.context());

  EXPECT_EQ(0U, builder_root.prefixes_with_context().size());
  EXPECT_EQ(0U, builder_root.exact_matches_with_context().size());

  ASSERT_EQ(2U, builder_root.children().size());

  // Check the 'test.' node
  auto* test_node = builder_root.FindChild("test");
  EXPECT_EQ("test", test_node->name());
  ASSERT_NE(nullptr, test_node->context());
  EXPECT_EQ("1st", *test_node->context());

  EXPECT_EQ(0U, test_node->children().size());
  EXPECT_EQ(1U, test_node->prefixes_with_context().size());
  {
    auto [prefix, context] = test_node->prefixes_with_context()[0];
    EXPECT_EQ("test", prefix);
    ASSERT_NE(nullptr, context);
    EXPECT_EQ("2nd", *context);
  }
  EXPECT_EQ(3U, test_node->exact_matches_with_context().size());
  EXPECT_EQ("test1", test_node->exact_matches_with_context()[0].first);
  EXPECT_EQ("test2", test_node->exact_matches_with_context()[1].first);
  EXPECT_EQ("test3", test_node->exact_matches_with_context()[2].first);

  ASSERT_NE(nullptr, test_node->exact_matches_with_context()[0].second);
  ASSERT_NE(nullptr, test_node->exact_matches_with_context()[1].second);
  ASSERT_NE(nullptr, test_node->exact_matches_with_context()[2].second);

  EXPECT_EQ("3rd", *test_node->exact_matches_with_context()[0].second);
  EXPECT_EQ("3rd", *test_node->exact_matches_with_context()[1].second);
  EXPECT_EQ("3rd", *test_node->exact_matches_with_context()[2].second);

  // Check the long string node
  auto expect_empty_one_child = [](auto* node) {
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(nullptr, node->context());
    EXPECT_EQ(0U, node->prefixes_with_context().size());
    EXPECT_EQ(0U, node->exact_matches_with_context().size());
    EXPECT_EQ(1U, node->children().size());
  };

  // Start with 'this'
  auto* long_string_node = builder_root.FindChild("this");
  expect_empty_one_child(long_string_node);

  // Move to 'is'
  long_string_node = long_string_node->FindChild("is");
  expect_empty_one_child(long_string_node);

  // Move to 'a'
  long_string_node = long_string_node->FindChild("a");
  expect_empty_one_child(long_string_node);

  // Move to 'long'
  long_string_node = long_string_node->FindChild("long");
  EXPECT_EQ(0U, long_string_node->prefixes_with_context().size());
  EXPECT_EQ(1U, long_string_node->exact_matches_with_context().size());
  EXPECT_EQ(0U, long_string_node->children().size());

  {
    auto [match, context] = long_string_node->exact_matches_with_context()[0];
    EXPECT_EQ("string", match);
    ASSERT_NE(nullptr, context);
    EXPECT_EQ("4th", *context);
  }
}

}  // namespace properties
}  // namespace android
