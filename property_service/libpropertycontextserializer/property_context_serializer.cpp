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

#include <set>

#include "trie_builder.h"
#include "trie_serializer.h"

namespace android {
namespace properties {

Result<std::string> BuildTrie(
    const std::vector<std::pair<std::string, std::string>>& prefixes_with_context,
    const std::vector<std::pair<std::string, std::string>>& exact_matches_with_context,
    const std::string& default_context) {
  // Check that names are legal first

  auto builder_root = TrieBuilderNode("root");
  auto contexts = std::set<std::string>();
  contexts.emplace(default_context);
  builder_root.set_context(&(*contexts.find(default_context)));

  for (const auto& [prefix, context] : prefixes_with_context) {
    if (auto result = AddToTrie(&builder_root, &contexts, prefix, context, false); !result) {
      return result.error();
    }
  }
  for (const auto& [exact_match, context] : exact_matches_with_context) {
    if (auto result = AddToTrie(&builder_root, &contexts, exact_match, context, true); !result) {
      return result.error();
    }
  }

  auto trie_serializer = TrieSerializer();
  return trie_serializer.SerializeTrie(builder_root, contexts);
}

}  // namespace properties
}  // namespace android
