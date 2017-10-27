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

#include "property_context_parser/property_context_parser.h"

#include <string.h>

namespace android {
namespace properties {

namespace {

// Binary search to find index of element 't' in an array compared via f(search).
template <typename F>
int Find(uint32_t array_length, F&& f) {
    int bottom = 0;
    int top = array_length - 1;
    while (top >= bottom) {
      int search = (top + bottom) / 2;

      auto cmp = f(search);

      if (cmp == 0) return search;
      if (cmp < 0) bottom = search + 1;
      if (cmp > 0) top = search - 1;
    }
    return -1;
}

}  // namespace

const char* mmap_base = nullptr;

// Binary search the list of contexts to find the index of a given context string.
// Only should be used for TrieSerializer to construct the Trie.
int PropertyContextArea::FindContextIndex(const char* context) const {
  uint32_t context_array_size_offset = contexts_offset();
  uint32_t context_array_size = uint32_array(context_array_size_offset)[0];
  uint32_t context_array_offset = context_array_size_offset + sizeof(uint32_t);
  return Find(context_array_size, [this, context, context_array_offset](auto array_offset) {
    auto string_offset = uint32_array(context_array_offset)[array_offset];
    return strcmp(string(string_offset), context);
  });
}

// Binary search the list of children nodes to find a TrieNode for a given property piece.
// Used to traverse the Trie in FindContextForProperty
const TrieNode* TrieNode::FindChildForString(const char* name, uint32_t namelen) const {
  auto node_index = Find(num_child_nodes_, [this, name, namelen](auto array_offset) {
    int cmp = strncmp(child_node(array_offset)->name_, name, namelen);
    if (cmp == 0 && child_node(array_offset)->name_[namelen] != '\0') {
      // We use strncmp() since name isn't null terminated, but we don't want to match only a prefix
      // of a child node's name, so we check here if we did only match a prefix and return 1, to
      // indicate to the binary search to search earlier in the array for the real match.
      return 1;
    }
    return cmp;
  });
  if (node_index == -1) return nullptr;
  return child_node(node_index);
}

const char* PropertyContextArea::FindContextForProperty(const char* name) const {
  const char* context = nullptr;
  const char* remaining_name = name;
  auto trie_node = root_node();
  while (true) {
    const char* sep = strchr(remaining_name, '.');

    // Apply prefix match for prefix deliminated with '.'
    if (trie_node->context()) {
      context = trie_node->context();
    }

    if (sep == nullptr) {
      break;
    }

    const uint32_t substr_size = sep - remaining_name;
    auto child_node = trie_node->FindChildForString(remaining_name, substr_size);
    if (child_node == nullptr) {
      break;
    }

    trie_node = child_node;
    remaining_name = sep + 1;
  }

  // We've made it to a leaf node, so check contents and return appropriately.
  // Check exact matches
  for (uint32_t i = 0; i < trie_node->num_exact_matches(); ++i) {
    if (!strcmp(trie_node->exact_match(i), remaining_name)) {
      return trie_node->exact_match_context(i);
    }
  }
  // Check prefix matches for prefixes not deliminated with '.'
  const uint32_t remaining_name_size = strlen(remaining_name);
  for (uint32_t i = 0; i < trie_node->num_prefixes(); ++i) {
    auto prefix_len = trie_node->prefix_len(i);
    if (prefix_len > remaining_name_size) continue;

    if (!strncmp(trie_node->prefix(i), remaining_name, prefix_len)) {
      return trie_node->prefix_context(i);
    }
  }
  // Return previously found '.' deliminated prefix match.
  return context;

}

}  // namespace properties
}  // namespace android
