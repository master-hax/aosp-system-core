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

#ifndef PROPERTY_CONTEXT_SERIALIZER_TRIE_SERIALIZER_H
#define PROPERTY_CONTEXT_SERIALIZER_TRIE_SERIALIZER_H

#include <string>
#include <vector>

#include "property_context_parser/property_context_parser.h"

#include "trie_builder.h"
#include "trie_node_arena.h"

namespace android {
namespace properties {

class TrieSerializer {
 public:
  TrieSerializer();

  std::string SerializeTrie(const TrieBuilder& trie_builder);

 private:
  void SerializeStrings(const std::set<std::string>& strings);
  uint32_t WritePropertyEntry(const PropertyEntryBuilder& property_entry);
  template <auto size_array, auto property_entry_offset_array>
  void WriteMatchArray(const std::vector<PropertyEntryBuilder>& sorted_matches,
                       uint32_t trie_offset);
  void WriteTriePrefixMatches(const TrieBuilderNode& builder_node, uint32_t trie_offset);
  void WriteTrieExactMatches(const TrieBuilderNode& builder_node, uint32_t trie_offset);

  // Creates a new TrieNode within arena, and recursively creates its children.
  // Returns the offset within arena.
  uint32_t CreateTrieNode(const TrieBuilderNode& builder_node);

  const PropertyContextArea* contexts() const {
    return reinterpret_cast<const PropertyContextArea*>(arena_->data().data());
  }

  std::unique_ptr<TrieNodeArena> arena_;
};

}  // namespace properties
}  // namespace android

#endif
