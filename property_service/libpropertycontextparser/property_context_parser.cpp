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

// Binary search to find index of element in an array compared via f(search).
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

// Binary search the list of contexts to find the index of a given context string.
// Only should be used for TrieSerializer to construct the Trie.
int PropertyContextArea::FindContextIndex(const char* context) const {
  return Find(num_contexts(), [this, context](auto array_offset) {
    auto string_offset = uint32_array(contexts_array_offset())[array_offset];
    return strcmp(string(string_offset), context);
  });
}

// Binary search the list of children nodes to find a TrieNode for a given property piece.
// Used to traverse the Trie in FindContextForProperty
bool TrieNode::FindChildForString(const char* name, uint32_t namelen, TrieNode* child) const {
  auto node_index =
      Find(trie_node_base_->num_child_nodes_, [this, name, namelen](auto array_offset) {
        const char* child_name = child_node(array_offset).name();
        int cmp = strncmp(child_name, name, namelen);
        if (cmp == 0 && child_name[namelen] != '\0') {
          // We use strncmp() since name isn't null terminated, but we don't want to match only a
          // prefix of a child node's name, so we check here if we did only match a prefix and
          // return 1, to indicate to the binary search to search earlier in the array for the real
          // match.
          return 1;
        }
        return cmp;
      });

  if (node_index == -1) {
    return false;
  }
  *child = child_node(node_index);
  return true;
}

uint32_t PropertyContextArea::FindContextIndexForProperty(const char* name) const {
  uint32_t return_context_index = ~0u;
  const char* remaining_name = name;
  auto trie_node = root_node();
  while (true) {
    const char* sep = strchr(remaining_name, '.');

    // Apply prefix match for prefix deliminated with '.'
    if (trie_node.context_index() != ~0u) {
      return_context_index = trie_node.context_index();
    }

    if (sep == nullptr) {
      break;
    }

    const uint32_t substr_size = sep - remaining_name;
    TrieNode child_node;
    if (!trie_node.FindChildForString(remaining_name, substr_size, &child_node)) {
      break;
    }

    trie_node = child_node;
    remaining_name = sep + 1;
  }

  // We've made it to a leaf node, so check contents and return appropriately.
  // Check exact matches
  for (uint32_t i = 0; i < trie_node.num_exact_matches(); ++i) {
    if (!strcmp(trie_node.exact_match(i), remaining_name)) {
      return trie_node.exact_match_context_index(i);
    }
  }
  // Check prefix matches for prefixes not deliminated with '.'
  const uint32_t remaining_name_size = strlen(remaining_name);
  for (uint32_t i = 0; i < trie_node.num_prefixes(); ++i) {
    auto prefix_len = trie_node.prefix_len(i);
    if (prefix_len > remaining_name_size) continue;

    if (!strncmp(trie_node.prefix(i), remaining_name, prefix_len)) {
      return trie_node.prefix_context_index(i);
    }
  }
  // Return previously found '.' deliminated prefix match.
  return return_context_index;
}

const char* PropertyContextArea::FindContextForProperty(const char* property) const {
  auto index = FindContextIndexForProperty(property);
  if (index == ~0u) return nullptr;
  return context(index);
}

}  // namespace properties
}  // namespace android
