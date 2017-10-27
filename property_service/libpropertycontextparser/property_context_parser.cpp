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

// Binary search to find index of element 't' in an array accessed via f(index) up to array_length.
template <typename T, typename F>
int Find(T&& t, uint32_t array_length, F&& f) {
    uint32_t bottom = 0;
    uint32_t top = array_length - 1;
    while (top > bottom) {
      uint32_t search = (top + bottom) / 2;
      auto comparison_target = f(search);
      auto cmp = strcmp(comparison_target, t);

      if (cmp == 0) return search;
      if (cmp < 0) bottom = search + 1;
      if (cmp > 0) top = search - 1;
    }
    return -1;
}

}  // namespace

const char* TrieNode::mmap_base_;

int Contexts::FindContextIndex(const char* context) {
  return Find(context, array_size(), [this](auto n) {
    return context_pointer(n);
  });
}

const TrieNode* TrieNode::FindNodeForString(const char* input) {
  auto node_index = Find(input, num_child_nodes_, [this](auto search) {
    return child_node(search)->name();
  });
  if (node_index == -1) return nullptr;
  return child_node(node_index);
}

}  // namespace properties
}  // namespace android
