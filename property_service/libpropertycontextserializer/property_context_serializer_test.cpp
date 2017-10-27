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

#include "property_context_serializer/property_context_serializer.h"

#include "property_context_parser/property_context_parser.h"

#include <gtest/gtest.h>

namespace android {
namespace properties {

TEST(propertycontextserializer, EndToEnd) {
  auto prefixes_with_context = std::vector<std::pair<std::string, std::string>>{
    {"test.", "1st"},
    {"test.test", "2nd"},
  };
  auto exact_matches_with_context = std::vector<std::pair<std::string, std::string>>{
    {"test.test1", "3rd"},
    {"test.test2", "3rd"},
    {"test.test3", "3rd"},
    {"this.is.a.long.string", "4th"},
  };

  auto serialized_trie = BuildTrie(prefixes_with_context, exact_matches_with_context, "default");
  ASSERT_TRUE(serialized_trie) << serialized_trie.error();

  auto property_context_area = reinterpret_cast<PropertyContextArea*>(serialized_trie->data());
  TrieNode::mmap_base_ = serialized_trie->data();

  // Initial checks for property area.
  EXPECT_EQ(1U, property_context_area->version());

  // Check the root node
  auto root_node = property_context_area->root_node();
  EXPECT_STREQ("root", root_node->name());
  EXPECT_STREQ("default", root_node->context());

  EXPECT_EQ(0U, root_node->num_prefixes());
  EXPECT_EQ(0U, root_node->num_exact_matches());

  ASSERT_EQ(2U, root_node->num_child_nodes());

  // Check the 'test'. node
  auto test_node = root_node->FindChildForString("test", 4);
  ASSERT_NE(nullptr, test_node);

  EXPECT_STREQ("test", test_node->name());
  EXPECT_STREQ("1st", test_node->context());

  EXPECT_EQ(0U, test_node->num_child_nodes());

  EXPECT_EQ(1U, test_node->num_prefixes());
  EXPECT_STREQ("test", test_node->prefix(0));
  EXPECT_STREQ("2nd", test_node->prefix_context(0));

  EXPECT_EQ(3U, test_node->num_exact_matches());
  EXPECT_STREQ("test1", test_node->exact_match(0));
  EXPECT_STREQ("test2", test_node->exact_match(1));
  EXPECT_STREQ("test3", test_node->exact_match(2));

  EXPECT_STREQ("3rd", test_node->exact_match_context(0));
  EXPECT_STREQ("3rd", test_node->exact_match_context(1));
  EXPECT_STREQ("3rd", test_node->exact_match_context(2));

  // Check the long string node
  auto expect_empty_one_child = [](auto* node) {
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(nullptr, node->context());
    EXPECT_EQ(0U, node->num_prefixes());
    EXPECT_EQ(0U, node->num_exact_matches());
    EXPECT_EQ(1U, node->num_child_nodes());
  };

  // Start with 'this'
  auto* long_string_node = root_node->FindChildForString("this", 4);
  expect_empty_one_child(long_string_node);

  // Move to 'is'
  long_string_node = long_string_node->FindChildForString("is", 2);
  expect_empty_one_child(long_string_node);

  // Move to 'a'
  long_string_node = long_string_node->FindChildForString("a", 1);
  expect_empty_one_child(long_string_node);

  // Move to 'long'
  long_string_node = long_string_node->FindChildForString("long", 4);
  EXPECT_EQ(0U, long_string_node->num_prefixes());
  EXPECT_EQ(1U, long_string_node->num_exact_matches());
  EXPECT_EQ(0U, long_string_node->num_child_nodes());

  EXPECT_STREQ("string", long_string_node->exact_match(0));
  EXPECT_STREQ("4th", long_string_node->exact_match_context(0));
}

}  // namespace properties
}  // namespace android
