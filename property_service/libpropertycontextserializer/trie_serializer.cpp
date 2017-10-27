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
uint32_t TrieSerializer::SerializeContexts(const std::set<std::string>& contexts) {
  uint32_t context_area_offset;
  arena_->AllocateUint32(contexts.size(), &context_area_offset);

  // Allocate space for the array.
  uint32_t* offset_array = arena_->AllocateUint32Array(contexts.size(), nullptr);

  // Write offset pointers and strings.
  auto it = contexts.begin();
  for (unsigned int i = 0; i < contexts.size(); ++i, ++it) {
    uint32_t string_offset;
    arena_->AllocateString(*it, &string_offset);

    offset_array[i] = string_offset;
  }
  return context_area_offset;
}

template <auto size_array, auto match_offset_array_offset, auto context_offset_array_offset>
void TrieSerializer::WriteMatchArray(
    const std::vector<std::pair<std::string, const std::string*>>& sorted_matches,
    TrieNode* trie_node) {
  trie_node->*size_array = sorted_matches.size();
  uint32_t* match_offset_array =
      arena_->AllocateUint32Array(sorted_matches.size(), &(trie_node->*match_offset_array_offset));
  uint32_t* context_offset_array =
      arena_->AllocateUint32Array(sorted_matches.size(), &(trie_node->*context_offset_array_offset));

  for (unsigned int i = 0; i < sorted_matches.size(); ++i) {
    const auto& [match, context_pointer] = sorted_matches[i];
    arena_->AllocateString(match, &match_offset_array[i]);
    context_offset_array[i] = contexts_->FindContextOffset(context_pointer->c_str());
  }
}

void TrieSerializer::WriteTriePrefixMatches(const TrieBuilderNode& builder_node, TrieNode* trie_node) {
  auto sorted_matches = builder_node.prefixes_with_context();
  // Prefixes are sorted by descending length
  std::sort(sorted_matches.begin(), sorted_matches.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.first.size() > rhs.first.size();
  });
  WriteMatchArray<&TrieNode::num_prefixes_, &TrieNode::prefixes_, &TrieNode::prefix_contexts_>
      (sorted_matches, trie_node);
}

void TrieSerializer::WriteTrieExactMatches(const TrieBuilderNode& builder_node, TrieNode* trie_node) {
  auto sorted_matches = builder_node.exact_matches_with_context();
  // Exact matches are sorted alphabetically
  std::sort(sorted_matches.begin(), sorted_matches.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.first < rhs.first;
  });
  WriteMatchArray<&TrieNode::num_exact_matches_, &TrieNode::exact_matches_,
                  &TrieNode::exact_match_contexts_>(sorted_matches, trie_node);
}

uint32_t TrieSerializer::CreateTrieNode(const TrieBuilderNode& builder_node) {
  uint32_t offset;
  auto* trie_node = arena_->AllocateTrie(builder_node.name(), &offset);

  if (!builder_node.context()->empty()) {
    trie_node->context_ = contexts_->FindContextOffset(builder_node.context()->c_str());
  } else {
    trie_node->context_ = 0;
  }
  WriteTriePrefixMatches(builder_node, trie_node);
  WriteTrieExactMatches(builder_node, trie_node);

  auto sorted_children = builder_node.children();
  std::sort(sorted_children.begin(), sorted_children.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.name() < rhs.name();
  });

  trie_node->num_child_nodes_ = sorted_children.size();
  uint32_t* children_offset_array =
      arena_->AllocateUint32Array(sorted_children.size(), &trie_node->child_nodes_);

  for (unsigned int i = 0; i < sorted_children.size(); ++i) {
    children_offset_array[i] = CreateTrieNode(builder_node.children()[i]);
  }
  return offset;
}

TrieSerializer::TrieSerializer() {}

constexpr uint32_t kMagic = 0xabcdabcd;

std::string TrieSerializer::SerializeTrie(const TrieBuilderNode& builder_root,
                                          const std::set<std::string>& contexts) {
  arena_.reset(new TrieNodeArena());
  arena_->AllocateUint32(kMagic, nullptr);
  arena_->AllocateUint32(1, nullptr);

  uint32_t contexts_offset = SerializeContexts(contexts);
  auto contexts_pointer = arena_->AllocateUint32(contexts_offset, nullptr);

  // TODO: This is terrible
  contexts_.reset(new Contexts(reinterpret_cast<const char*>(contexts_pointer),
                               arena_->size() - 2 * sizeof(uint32_t)));

  uint32_t trie_offset = CreateTrieNode(builder_root);
  arena_->AllocateUint32(trie_offset, nullptr);

  return arena_->data();
}

}  // namespace properties
}  // namespace android
