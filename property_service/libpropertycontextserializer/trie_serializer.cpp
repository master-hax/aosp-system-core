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

// Serialized contexts contains:
// 1) A uint32_t count of elements in the below array
// 2) A sorted array of uint32_t offsets pointing to null terminated context strings
// 3) Each of the null terminated context strings themselves packed back to back
// This returns the offset into arena where the serialized contexts start.
void TrieSerializer::SerializeContexts(const std::set<std::string>& contexts) {
  arena_->AllocateAndWriteUint32(contexts.size());

  // Allocate space for the array.
  uint32_t offset_array_offset = arena_->AllocateUint32Array(contexts.size());

  // Write offset pointers and strings; these are already alphabetically sorted by virtue of being
  // in an std::set.
  auto it = contexts.begin();
  for (unsigned int i = 0; i < contexts.size(); ++i, ++it) {
    uint32_t string_offset = arena_->AllocateAndWriteString(*it);
    arena_->uint32_array(offset_array_offset)[i] = string_offset;
  }
}

template <auto size_array, auto match_offset_array_offset_pointer,
          auto match_size_array_offset_pointer, auto context_index_array_offset_pointer>
void TrieSerializer::WriteMatchArray(
    const std::vector<std::pair<std::string, const std::string*>>& sorted_matches,
    uint32_t trie_offset) {
  arena_->trie(trie_offset)->*size_array = sorted_matches.size();

  uint32_t match_offset_array_offset = arena_->AllocateUint32Array(sorted_matches.size());
  arena_->trie(trie_offset)->*match_offset_array_offset_pointer = match_offset_array_offset;

  uint32_t context_index_array_offset = arena_->AllocateUint32Array(sorted_matches.size());
  arena_->trie(trie_offset)->*context_index_array_offset_pointer = context_index_array_offset;

  uint32_t match_size_array_offset = 0;
  if constexpr (!std::is_same_v<decltype(match_size_array_offset_pointer), std::nullptr_t>) {
    match_size_array_offset = arena_->AllocateUint32Array(sorted_matches.size());
    arena_->trie(trie_offset)->*match_size_array_offset_pointer = match_size_array_offset;
  }

  for (unsigned int i = 0; i < sorted_matches.size(); ++i) {
    const auto& [match, context_pointer] = sorted_matches[i];

    uint32_t match_string_offset = arena_->AllocateAndWriteString(match);
    arena_->uint32_array(match_offset_array_offset)[i] = match_string_offset;

    uint32_t context_string_index = contexts()->FindContextIndex(context_pointer->c_str());
    arena_->uint32_array(context_index_array_offset)[i] = context_string_index;

    if (match_size_array_offset != 0) {
      arena_->uint32_array(match_size_array_offset)[i] = match.size();
    }
  }
}

void TrieSerializer::WriteTriePrefixMatches(const TrieBuilderNode& builder_node,
                                            uint32_t trie_offset) {
  auto sorted_matches = builder_node.prefixes_with_context();
  // Prefixes are sorted by descending length
  std::sort(sorted_matches.begin(), sorted_matches.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.first.size() > rhs.first.size(); });
  WriteMatchArray<&TrieNodeInternal::num_prefixes_, &TrieNodeInternal::prefixes_,
                  &TrieNodeInternal::prefix_lens_, &TrieNodeInternal::prefix_contexts_>(
      sorted_matches, trie_offset);
}

void TrieSerializer::WriteTrieExactMatches(const TrieBuilderNode& builder_node,
                                           uint32_t trie_offset) {
  auto sorted_matches = builder_node.exact_matches_with_context();
  // Exact matches are sorted alphabetically
  std::sort(sorted_matches.begin(), sorted_matches.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });

  WriteMatchArray<&TrieNodeInternal::num_exact_matches_, &TrieNodeInternal::exact_matches_, nullptr,
                  &TrieNodeInternal::exact_match_contexts_>(sorted_matches, trie_offset);
}

uint32_t TrieSerializer::CreateTrieNode(const TrieBuilderNode& builder_node) {
  uint32_t trie_offset = arena_->AllocateTrie(builder_node.name());

  if (builder_node.context() != nullptr && !builder_node.context()->empty()) {
    arena_->trie(trie_offset)->context_ =
        contexts()->FindContextIndex(builder_node.context()->c_str());
  } else {
    arena_->trie(trie_offset)->context_ = -1;
  }
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

std::string TrieSerializer::SerializeTrie(const TrieBuilderNode& builder_root,
                                          const std::set<std::string>& contexts) {
  arena_.reset(new TrieNodeArena());
  // Version
  // Size
  // Contexts Offset
  // Root TrieNode Offset
  auto header = arena_->AllocateUint32Array(4);
  arena_->uint32_array(header)[0] = 1;

  // Store where we're about to write the contexts
  arena_->uint32_array(header)[2] = arena_->size();
  SerializeContexts(contexts);

  // We need to store size() up to this point now for FindContextOffset() to work.
  arena_->uint32_array(header)[1] = arena_->size();

  uint32_t root_trie_offset = CreateTrieNode(builder_root);
  arena_->uint32_array(header)[3] = root_trie_offset;

  // Record the real size now that we've written everything
  arena_->uint32_array(header)[1] = arena_->size();

  return arena_->truncated_data();
}

}  // namespace properties
}  // namespace android
