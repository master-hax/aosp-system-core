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

class Contexts {
 public:
  Contexts(const char* data, size_t data_size) : data_(data), data_size_(data_size) {}

  uint32_t array_size() const {
    return *reinterpret_cast<const uint32_t*>(&data_[0]);
  }

  const uint32_t* array_base() const {
    return reinterpret_cast<const uint32_t*>(&data_[sizeof(uint32_t)]);
  }

  uint32_t context_offset(int index) const {
    return *(array_base() + index);
  }

  const char* context_pointer(int index) const {
    auto offset = context_offset(index);
    if (offset > data_size_) return nullptr;

    return data_ + offset;
  }

  int FindContextIndex(const char* context);

  uint32_t FindContextOffset(const char* context) {
    auto index = FindContextIndex(context);
    if (index == -1) return 0;
    return context_offset(index);
  }

  const char* FindContext(const char* context) {
    auto context_index = FindContextIndex(context);
    if (context_index == -1) return nullptr;
    return context_pointer(context_index);
  }

 private:
  const char* data_;
  size_t data_size_;
};

class TrieNode {
  friend class TrieNodeArena;
  friend class TrieSerializer;
 public:
  const char* name() const { return name_; }

  uint32_t num_child_nodes() const { return num_child_nodes_; }
  const TrieNode* child_node(int n) const {
    return &reinterpret_cast<const TrieNode*>(mmap_base_ + child_nodes_)[n];
  }

  const TrieNode* FindNodeForString(const char* input);

  uint32_t num_prefixes() const { return num_prefixes_; }
  const char* prefix(int n) const {
    return &reinterpret_cast<const char*>(mmap_base_ + prefixes_)[n];
  }
  const char* prefix_context(int n) const {
    return &reinterpret_cast<const char*>(mmap_base_ + prefix_contexts_)[n];
  }

  uint32_t num_exact_matches() const { return num_exact_matches_; }
  const char* exact_match(int n) const {
    return &reinterpret_cast<const char*>(mmap_base_ + exact_matches_)[n];
  }
  const char* exact_match_context(int n) const {
    return &reinterpret_cast<const char*>(mmap_base_ + exact_match_contexts_)[n];
  }

  const char* context() const {
    return mmap_base_ + context_;
  }

 private:
  static const char* mmap_base_;

  // Maybe we don't need namelen_ ?
  //uint32_t namelen_;

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
  uint32_t prefix_contexts_;

  // Exact matches are a sorted list of exact matches at this node_; binary search them.
  // If String(exact_matches[n]) matches, then String(exact_match_contexts[n]) is the context.
  uint32_t num_exact_matches_;
  uint32_t exact_matches_;
  uint32_t exact_match_contexts_;

  char name_[0];
};

}  // namespace properties
}  // namespace android

#endif
