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

struct TrieNodeInternal {
  uint32_t namelen_;

  // This is the context match for this node_; ~0u if it doesn't correspond to any.
  uint32_t context_;

  // Children are a sorted list of child nodes_; binary search them.
  // Check their name via Node(child_nodes[n])->name
  uint32_t num_child_nodes_;
  uint32_t child_nodes_;

  // Prefixes are terminating prefix matches at this node, sorted longest to smallest
  // Take the first match sequentially found with StartsWith().
  // If String(prefix[n]) matches, then prefix_contexts[n] is the index of the context within
  // the contexts array.
  uint32_t num_prefixes_;
  uint32_t prefixes_;
  uint32_t prefix_lens_;
  uint32_t prefix_contexts_;

  // Exact matches are a sorted list of exact matches at this node_; binary search them.
  // If String(exact_matches[n]) matches, then exact_match_contexts[n] is the index of the context
  // within the contexts array.
  uint32_t num_exact_matches_;
  uint32_t exact_matches_;
  uint32_t exact_match_contexts_;

  char name_[0];
};

class SerializedData {
 public:
  uint32_t size() const { return uint32_array(0)[1]; }

  const char* string(uint32_t offset) const {
    if (offset != 0 && offset > size()) return nullptr;
    return static_cast<const char*>(data_base_ + offset);
  }

  const uint32_t* uint32_array(uint32_t offset) const {
    if (offset != 0 && offset > size()) return nullptr;
    return reinterpret_cast<const uint32_t*>(data_base_ + offset);
  }

  uint32_t uint32(uint32_t offset) const {
    if (offset != 0 && offset > size()) return ~0u;
    return *reinterpret_cast<const uint32_t*>(data_base_ + offset);
  }

  const char* data_base() const { return data_base_; }

 protected:
  const char data_base_[0];
};

class TrieNode {
 public:
  TrieNode() : data_base_(nullptr), trie_node_base_(nullptr) {}
  TrieNode(const SerializedData* data_base, const TrieNodeInternal* trie_node_base)
      : data_base_(data_base), trie_node_base_(trie_node_base) {}

  const char* name() const { return trie_node_base_->name_; }

  uint32_t num_child_nodes() const { return trie_node_base_->num_child_nodes_; }
  TrieNode child_node(int n) const {
    uint32_t child_node_offset = data_base_->uint32_array(trie_node_base_->child_nodes_)[n];
    const TrieNodeInternal* trie_node_base =
        reinterpret_cast<const TrieNodeInternal*>(data_base_->data_base() + child_node_offset);
    return TrieNode(data_base_, trie_node_base);
  }

  bool FindChildForString(const char* input, uint32_t namelen, TrieNode* child) const;

  uint32_t num_prefixes() const { return trie_node_base_->num_prefixes_; }
  const char* prefix(int n) const {
    uint32_t prefix_offset = data_base_->uint32_array(trie_node_base_->prefixes_)[n];
    return data_base_->string(prefix_offset);
  }
  uint32_t prefix_len(int n) const {
    return data_base_->uint32_array(trie_node_base_->prefix_lens_)[n];
  }
  uint32_t prefix_context_index(int n) const {
    return data_base_->uint32_array(trie_node_base_->prefix_contexts_)[n];
  }

  uint32_t num_exact_matches() const { return trie_node_base_->num_exact_matches_; }
  const char* exact_match(int n) const {
    uint32_t exact_match_offset = data_base_->uint32_array(trie_node_base_->exact_matches_)[n];
    return data_base_->string(exact_match_offset);
  }
  uint32_t exact_match_context_index(int n) const {
    return data_base_->uint32_array(trie_node_base_->exact_match_contexts_)[n];
  }

  uint32_t context_index() const { return trie_node_base_->context_; }

 private:
  const SerializedData* data_base_;
  const TrieNodeInternal* trie_node_base_;
};

class PropertyContextArea : private SerializedData {
 public:
  uint32_t FindContextIndexForProperty(const char* property) const;

  const char* FindContextForProperty(const char* property) const;

  int FindContextIndex(const char* context) const;

  const char* context(uint32_t index) const {
    uint32_t context_array_size_offset = contexts_offset();
    const uint32_t* context_array = uint32_array(context_array_size_offset + sizeof(uint32_t));
    return data_base_ + context_array[index];
  }

  uint32_t version() const { return uint32_array(0)[0]; }

  uint32_t size() const { return SerializedData::size(); }

  uint32_t num_contexts() const { return uint32_array(contexts_offset())[0]; }

  TrieNode root_node() const { return trie(uint32_array(0)[3]); }

 private:
  uint32_t contexts_offset() const { return uint32_array(0)[2]; }
  uint32_t contexts_array_offset() const { return contexts_offset() + sizeof(uint32_t); }

  TrieNode trie(uint32_t offset) const {
    if (offset != 0 && offset > size()) return TrieNode();
    const TrieNodeInternal* trie_node_base =
        reinterpret_cast<const TrieNodeInternal*>(data_base_ + offset);
    return TrieNode(this, trie_node_base);
  }
};

}  // namespace properties
}  // namespace android

#endif
