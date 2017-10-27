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

#ifndef PROPERTY_CONTEXT_PARSER_H
#define PROPERTY_CONTEXT_PARSER_H

#include <stdint.h>

namespace android {
namespace properties {

class TrieNode {
  friend class TrieNodeArena;
  friend class TrieSerializer;
 public:
  const char* name() const { return name_; }

  uint32_t num_child_nodes() const { return num_child_nodes_; }
  const TrieNode* child_node(int n) const {
    uint32_t child_node_offset = reinterpret_cast<const uint32_t*>(mmap_base_ + child_nodes_)[n];
    return reinterpret_cast<const TrieNode*>(mmap_base_ + child_node_offset);
  }

  const TrieNode* FindChildForString(const char* input, uint32_t namelen) const;

  uint32_t num_prefixes() const { return num_prefixes_; }
  const char* prefix(int n) const {
    uint32_t prefix_offset = reinterpret_cast<const uint32_t*>(mmap_base_ + prefixes_)[n];
    return reinterpret_cast<const char*>(mmap_base_ + prefix_offset);
  }
  uint32_t prefix_len(int n) const {
    return reinterpret_cast<const uint32_t*>(mmap_base_ + prefix_lens_)[n];
  }
  const char* prefix_context(int n) const {
    uint32_t prefix_context_offset =
        reinterpret_cast<const uint32_t*>(mmap_base_ + prefix_contexts_)[n];
    return reinterpret_cast<const char*>(mmap_base_ + prefix_context_offset);
  }

  uint32_t num_exact_matches() const { return num_exact_matches_; }
  const char* exact_match(int n) const {
    uint32_t exact_match_offset =
        reinterpret_cast<const uint32_t*>(mmap_base_ + exact_matches_)[n];
    return reinterpret_cast<const char*>(mmap_base_ + exact_match_offset);
  }
  const char* exact_match_context(int n) const {
    uint32_t exact_match_context_offset =
        reinterpret_cast<const uint32_t*>(mmap_base_ + exact_match_contexts_)[n];
    return reinterpret_cast<const char*>(mmap_base_ + exact_match_context_offset);
  }

  const char* context() const {
    if (context_ == 0) return nullptr;
    return mmap_base_ + context_;
  }

  static const char* mmap_base_;

 private:
  uint32_t namelen_;

  // This is the context match for this node_; 0 if it doesn't correspond to any.
  uint32_t context_;

  // Children are a sorted list of child nodes_; binary search them.
  // Check their name via Node(child_nodes[n])->name
  uint32_t num_child_nodes_;
  uint32_t child_nodes_;

  // Prefixes are terminating prefix matches at this node, sorted longest to smallest
  // Take the first match sequentially found with StartsWith().
  // If String(prefix[n]) matches, then String(prefix_contexts[n]) is the context.
  uint32_t num_prefixes_;
  uint32_t prefixes_;
  uint32_t prefix_lens_;
  uint32_t prefix_contexts_;

  // Exact matches are a sorted list of exact matches at this node_; binary search them.
  // If String(exact_matches[n]) matches, then String(exact_match_contexts[n]) is the context.
  uint32_t num_exact_matches_;
  uint32_t exact_matches_;
  uint32_t exact_match_contexts_;

  char name_[0];
};

class PropertyContextArea {
 public:
  const char* FindContextForProperty(const char* property) const;

  int FindContextIndex(const char* context) const;

  uint32_t FindContextOffset(const char* context) const {
    auto index = FindContextIndex(context);
    if (index == -1) return 0;

    uint32_t context_array_size_offset = contexts_offset();
    const uint32_t* context_array = uint32_array(context_array_size_offset + sizeof(uint32_t));
    return context_array[index];
  }

  uint32_t version() const {
    return uint32_array(0)[0];
  }

  uint32_t size() const {
    return uint32_array(0)[1];
  }

  uint32_t contexts_offset() const {
    return uint32_array(0)[2];
  }

  const TrieNode* root_node() const {
    return trie(uint32_array(0)[3]);
  }

  const TrieNode* trie(uint32_t offset) const {
    if (offset != 0 && offset > size()) return nullptr;
    return reinterpret_cast<const TrieNode*>(data_ + offset);
  }

  const char* string(uint32_t offset) const {
    if (offset != 0 && offset > size()) return nullptr;
    return static_cast<const char*>(data_ + offset);
  }

  const uint32_t* uint32_array(uint32_t offset) const {
    if (offset != 0 && offset > size()) return nullptr;
    return reinterpret_cast<const uint32_t*>(data_ + offset);
  }

 private:
  const char data_[0];
};

}  // namespace properties
}  // namespace android

#endif
