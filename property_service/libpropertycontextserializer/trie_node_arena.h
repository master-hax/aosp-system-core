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

#ifndef PROPERTY_CONTEXT_SERIALIZER_TRIE_NODE_ARENA_H
#define PROPERTY_CONTEXT_SERIALIZER_TRIE_NODE_ARENA_H

#include <string>

namespace android {
namespace properties {

class TrieNodeArena {
 public:
  TrieNodeArena() : data_(5000, '\0') {}

  TrieNode* AllocateTrie(const std::string& name, uint32_t* offset) {
    void* data = AllocateData(sizeof(TrieNode) + name.size() + 1, offset);
    auto trie_node = new (data) TrieNode();
    strcpy(trie_node->name_, name.c_str());
    //trie_node->namelen_ = name.size();
    return trie_node;
  }

  uint32_t* AllocateUint32Array(int length, uint32_t* offset) {
    return static_cast<uint32_t*>(AllocateData(sizeof(uint32_t) * length, offset));
  }

  char* AllocateString(const std::string& string, uint32_t* offset) {
    char* result = static_cast<char*>(AllocateData(string.size() + 1, offset));
    strcpy(result, string.c_str());
    return result;
  }

  uint32_t* AllocateUint32(uint32_t value, uint32_t* offset) {
    auto location = static_cast<uint32_t*>(AllocateData(sizeof(uint32_t), offset));
    *location = value;
    return location;
  }

  void* AllocateData(size_t size, uint32_t* offset) {
    if (current_data_pointer_ + size > data_.size()) {
      auto new_size = (current_data_pointer_ + size + data_.size()) * 2;
      data_.resize(new_size, '\0');
    }
    if (*offset) *offset = current_data_pointer_;

    uint32_t return_offset = current_data_pointer_;
    current_data_pointer_ += size;
    return &data_[0] + return_offset;
  }

  uint32_t size() const {
    return current_data_pointer_;
  }

  uint32_t capacity() const {
    return data_.size();
  }

  const std::string& data() {
    data_.resize(current_data_pointer_);
    return data_;
  }

 private:
  std::string data_;
  uint32_t current_data_pointer_;
};

}  // namespace properties
}  // namespace android

#endif
