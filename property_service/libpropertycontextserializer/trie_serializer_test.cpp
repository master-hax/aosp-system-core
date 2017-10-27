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

#include "trie_serializer.h"

#include <gtest/gtest.h>

namespace android {
namespace properties {

TEST(propertycontextserializer, SerializeTrie_Simple) {
  TrieBuilderNode builder_root("root");
  std::set<std::string> contexts;

  // Add test data to tree
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "tes.", "1st", false));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "tes.tes", "2nd", false));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "tes.te1", "3rd", true));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "tes.te2", "3rd", true));
  EXPECT_TRUE(AddToTrie(&builder_root, &contexts, "te2.te3", "3rd", true));

  auto trie_serializer = TrieSerializer();
  auto result = trie_serializer.SerializeTrie(builder_root, contexts);
  auto expected_header = "\x01\x00\x00\x00"s +  // 0 Version
                         "\xFF\xFF\xFF\xFF"s +  // 4 Size (TODO)
                         "\x10\x00\x00\x00"s +  // 8 Contexts Offset
                         "\xFF\xFF\xFF\xFF"s +  // 12 Root TrieNode Offset
                         // Contexts starts here
                         "\x04\x00\x00\x00"s +  // 16 Number of elements in contexts array
                         // Contexts array starts here
                         "\x24\x00\x00\x00"s +  // 20 1st context offset
                         "\x28\x00\x00\x00"s +  // 24 2st context offset
                         "\x2C\x00\x00\x00"s +  // 28 3st context offset
                         "\x30\x00\x00\x00"s +  // 32 4st context offset
                         "1st\x00"s +           // 36 1st context string
                         "2nd\x00"s +           // 40 2nd context string
                         "3rd\x00"s +           // 44 3rd context string
                         "4th\x00"s +           // 48 4th context string
                         // Root TrieNode
                         "\x03\x00\x00\x00"s +  // 52 rootnode namelen
                         "\x00\x00\x00\x00"s +  // 56 rootnode context
                         "\x02\x00\x00\x00"s +  // 60 rootnode num_children nodes
                         "\x00\x00\x00\x00"s +  // 64 rootnode child_nodes (TODO)
                         "\x01\x00\x00\x00"s +  // 68 rootnode num_prefixes
                         "\x00\x00\x00\x00"s +  // 72 rootnode prefixes (TODO)
                         "\x00\x00\x00\x00"s +  // 76 rootnode prefix lens (TODO)
}

}  // namespace properties
}  // namespace android
