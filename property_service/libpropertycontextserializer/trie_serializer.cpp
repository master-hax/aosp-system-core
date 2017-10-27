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

namespace android {
namespace properties {

// Serialized strings contains:
// 1) A uint32_t count of elements in the below array
// 2) A sorted array of uint32_t offsets pointing to null terminated strings
// 3) Each of the null terminated strings themselves packed back to back
// This returns the offset into arena where the serialized strings start.
void TrieSerializer::SerializeStrings(const std::set<std::string>& strings) {
  arena_->AllocateAndWriteUint32(strings.size());

  // Allocate space for the array.
  uint32_t offset_array_offset = arena_->AllocateUint32Array(strings.size());

  // Write offset pointers and strings; these are already alphabetically sorted by virtue of being
  // in an std::set.
  auto it = strings.begin();
  for (unsigned int i = 0; i < strings.size(); ++i, ++it) {
    uint32_t string_offset = arena_->AllocateAndWriteString(*it);
    arena_->uint32_array(offset_array_offset)[i] = string_offset;
  }
}

uint32_t TrieSerializer::WritePropertyEntry(const PropertyEntryBuilder& property_entry) {
  uint32_t context_index = property_entry.context != nullptr && !property_entry.context->empty()
                               ? contexts()->FindContextIndex(property_entry.context->c_str())
                               : ~0u;
  uint32_t schema_index = property_entry.schema != nullptr && !property_entry.schema->empty()
                              ? contexts()->FindSchemaIndex(property_entry.schema->c_str())
                              : ~0u;
  return arena_->AllocatePropertyEntry(property_entry.name, context_index, schema_index);
}

template <auto size_array, auto property_entry_offset_array>
void TrieSerializer::WriteMatchArray(const std::vector<PropertyEntryBuilder>& sorted_matches,
                                     uint32_t trie_offset) {
  arena_->trie(trie_offset)->*size_array = sorted_matches.size();

  uint32_t property_entry_offset_array_offset = arena_->AllocateUint32Array(sorted_matches.size());
  arena_->trie(trie_offset)->*property_entry_offset_array = property_entry_offset_array_offset;

  for (unsigned int i = 0; i < sorted_matches.size(); ++i) {
    uint32_t property_entry_offset = WritePropertyEntry(sorted_matches[i]);
    arena_->uint32_array(property_entry_offset_array_offset)[i] = property_entry_offset;
  }
}

void TrieSerializer::WriteTriePrefixMatches(const TrieBuilderNode& builder_node,
                                            uint32_t trie_offset) {
  auto sorted_matches = builder_node.prefixes();
  // Prefixes are sorted by descending length
  std::sort(sorted_matches.begin(), sorted_matches.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.name.size() > rhs.name.size(); });
  WriteMatchArray<&TrieNodeInternal::num_prefixes_, &TrieNodeInternal::prefix_entries_>(
      sorted_matches, trie_offset);
}

void TrieSerializer::WriteTrieExactMatches(const TrieBuilderNode& builder_node,
                                           uint32_t trie_offset) {
  auto sorted_matches = builder_node.exact_matches();
  // Exact matches are sorted alphabetically
  std::sort(sorted_matches.begin(), sorted_matches.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.name < rhs.name; });

  WriteMatchArray<&TrieNodeInternal::num_exact_matches_, &TrieNodeInternal::exact_match_entries_>(
      sorted_matches, trie_offset);
}

uint32_t TrieSerializer::CreateTrieNode(const TrieBuilderNode& builder_node) {
  uint32_t trie_offset = arena_->AllocateTrie();

  arena_->trie(trie_offset)->property_entry_ = WritePropertyEntry(builder_node.property_entry());

  WriteTriePrefixMatches(builder_node, trie_offset);
  WriteTrieExactMatches(builder_node, trie_offset);

  auto sorted_children = builder_node.children();
  std::sort(sorted_children.begin(), sorted_children.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.name() < rhs.name(); });

  arena_->trie(trie_offset)->num_child_nodes_ = sorted_children.size();
  uint32_t children_offset_array_offset = arena_->AllocateUint32Array(sorted_children.size());
  arena_->trie(trie_offset)->child_nodes_ = children_offset_array_offset;

  for (unsigned int i = 0; i < sorted_children.size(); ++i) {
    arena_->uint32_array(children_offset_array_offset)[i] = CreateTrieNode(sorted_children[i]);
  }
  return trie_offset;
}

TrieSerializer::TrieSerializer() {}

std::string TrieSerializer::SerializeTrie(const TrieBuilder& trie_builder) {
  arena_.reset(new TrieNodeArena());
  // Version
  // Size
  // Contexts Offset
  // Schemas Offset
  // Root TrieNode Offset
  auto header = arena_->AllocateUint32Array(5);
  arena_->uint32_array(header)[0] = 1;

  // Store where we're about to write the contexts.
  arena_->uint32_array(header)[2] = arena_->size();
  SerializeStrings(trie_builder.contexts());

  // Store where we're about to write the schemas.
  arena_->uint32_array(header)[3] = arena_->size();
  SerializeStrings(trie_builder.schemas());

  // We need to store size() up to this point now for Find*Offset() to work.
  arena_->uint32_array(header)[1] = arena_->size();

  uint32_t root_trie_offset = CreateTrieNode(trie_builder.builder_root());
  arena_->uint32_array(header)[4] = root_trie_offset;

  // Record the real size now that we've written everything
  arena_->uint32_array(header)[1] = arena_->size();

  return arena_->truncated_data();
}

}  // namespace properties
}  // namespace android
