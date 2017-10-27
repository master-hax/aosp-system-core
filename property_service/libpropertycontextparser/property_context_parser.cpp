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
    uint32_t bottom = 0;
    uint32_t top = array_length - 1;
    while (top > bottom) {
      uint32_t search = (top + bottom) / 2;

      auto cmp = f(search);

      if (cmp == 0) return search;
      if (cmp < 0) bottom = search + 1;
      if (cmp > 0) top = search - 1;
    }
    return -1;
}

}  // namespace

const char* TrieNode::mmap_base_;

// Binary search the list of contexts to find the index of a given context string.
// Only should be used for TrieSerializer to construct the Trie.
int PropertyContextArea::FindContextIndex(const char* context) const {
  uint32_t context_array_size_offset = contexts_offset();
  uint32_t context_array_size = uint32_array(context_array_size_offset)[0];
  return Find(context_array_size, [this, context](auto offset) {
    return strcmp(string(offset), context);
  });
}

// Binary search the list of children nodes to find a TrieNode for a given property piece.
// Used to traverse the Trie in FindContextForProperty
const TrieNode* TrieNode::FindChildForString(const char* name, uint32_t namelen) const {
  auto node_index = Find(num_child_nodes_, [this, name, namelen](auto search) {
    uint32_t child_len = child_node(search)->namelen_;
    if (child_len < namelen) return -1;
    if (child_len > namelen) return 1;
    return strncmp(child_node(search)->name_, name, namelen);
  });
  if (node_index == -1) return nullptr;
  return child_node(node_index);
}

const char* PropertyContextArea::FindContextForProperty(const char* name) const {
  const char* context = "";
  const char* remaining_name = name;
  auto trie_node = root_node();
  while (true) {
    const char* sep = strchr(remaining_name, '.');

    // Apply prefix match for prefix deliminated with '.'
    if (trie_node->context()) {
      context = trie_node->context();
    }

    if (sep == nullptr) {
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

    const uint32_t substr_size = sep - remaining_name;
    trie_node = trie_node->FindChildForString(remaining_name, substr_size);

    remaining_name = sep + 1;
  }
}

}  // namespace properties
}  // namespace android
