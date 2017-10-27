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
#include <vector>

namespace android {
namespace properties {

class TrieNodeArena {
 public:
  TrieNodeArena() : current_data_pointer_(0) {}

  uint32_t AllocateTrie() {
    uint32_t offset;
    AllocateData(sizeof(TrieNodeInternal), &offset);
    return offset;
  }

  uint32_t AllocatePropertyEntry(const std::string& name, uint32_t context_index,
                                 uint32_t schema_index) {
    uint32_t offset;
    void* data = AllocateData(sizeof(PropertyEntry) + name.size() + 1, &offset);
    auto property_entry = new (data) PropertyEntry();
    strcpy(property_entry->name, name.c_str());
    property_entry->namelen = name.size();
    property_entry->context_index = context_index;
    property_entry->schema_index = schema_index;
    return offset;
  }

  TrieNodeInternal* trie(uint32_t offset) {
    return reinterpret_cast<TrieNodeInternal*>(data_.data() + offset);
  }

  uint32_t AllocateUint32Array(int length) {
    uint32_t offset;
    AllocateData(sizeof(uint32_t) * length, &offset);
    return offset;
  }

  uint32_t* uint32_array(uint32_t offset) {
    return reinterpret_cast<uint32_t*>(data_.data() + offset);
  }

  uint32_t AllocateAndWriteString(const std::string& string) {
    uint32_t offset;
    char* data = static_cast<char*>(AllocateData(string.size() + 1, &offset));
    strcpy(data, string.c_str());
    return offset;
  }

  void AllocateAndWriteUint32(uint32_t value) {
    auto location = static_cast<uint32_t*>(AllocateData(sizeof(uint32_t), nullptr));
    *location = value;
  }

  void* AllocateData(size_t size, uint32_t* offset) {
    size_t aligned_size = size + (sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);

    if (current_data_pointer_ + aligned_size > data_.size()) {
      auto new_size = (current_data_pointer_ + aligned_size + data_.size()) * 2;
      data_.resize(new_size, '\0');
    }
    if (offset) *offset = current_data_pointer_;

    uint32_t return_offset = current_data_pointer_;
    current_data_pointer_ += aligned_size;
    return &data_[0] + return_offset;
  }

  uint32_t size() const { return current_data_pointer_; }

  const std::string& data() const { return data_; }

  std::string truncated_data() const {
    auto result = data_;
    result.resize(current_data_pointer_);
    return result;
  }

 private:
  std::string data_;
  uint32_t current_data_pointer_;
};

}  // namespace properties
}  // namespace android

#endif
