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

#ifndef PROPERTY_CONTEXT_SERIALIZER_TRIE_BUILDER_H
#define PROPERTY_CONTEXT_SERIALIZER_TRIE_BUILDER_H

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace android {
namespace properties {

class TrieBuilderNode {
 public:
  TrieBuilderNode(const std::string& name) : name_(name), context_(nullptr) {}

  TrieBuilderNode* FindChild(const std::string& name) {
    for (auto& child : children_) {
      if (child.name_ == name) return &child;
    }
    return nullptr;
  }

  TrieBuilderNode* AddChild(const std::string& name) { return &children_.emplace_back(name); }

  bool AddPrefixContext(const std::string& prefix, const std::string* context) {
    if (std::find_if(prefixes_with_context_.begin(), prefixes_with_context_.end(),
                     [&prefix](const auto& t) { return t.first == prefix; }) !=
        prefixes_with_context_.end()) {
      return false;
    }

    prefixes_with_context_.emplace_back(prefix, context);
    return true;
  }

  bool AddExactMatchContext(const std::string& exact_match, const std::string* context) {
    if (std::find_if(exact_matches_with_context_.begin(), exact_matches_with_context_.end(),
                     [&exact_match](const auto& t) { return t.first == exact_match; }) !=
        exact_matches_with_context_.end()) {
      return false;
    }

    exact_matches_with_context_.emplace_back(exact_match, context);
    return true;
  }

  const std::string& name() const { return name_; }
  const std::string* context() const { return context_; }
  void set_context(const std::string* context) { context_ = context; }
  const std::vector<TrieBuilderNode>& children() const { return children_; }
  const std::vector<std::pair<std::string, const std::string*>>& prefixes_with_context() const {
    return prefixes_with_context_;
  }
  const std::vector<std::pair<std::string, const std::string*>>& exact_matches_with_context() const {
    return exact_matches_with_context_;
  }

 private:
  std::string name_;
  const std::string* context_;
  std::vector<TrieBuilderNode> children_;
  std::vector<std::pair<std::string, const std::string*>> prefixes_with_context_;
  std::vector<std::pair<std::string, const std::string*>> exact_matches_with_context_;
};

bool AddToTrie(TrieBuilderNode* builder_root, std::set<std::string>* contexts,
               const std::string& name, const std::string& context, bool exact, std::string* error);

}  // namespace properties
}  // namespace android

#endif
