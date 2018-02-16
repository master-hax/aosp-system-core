/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _INIT_CONTEXT_LIST_H
#define _INIT_CONTEXT_LIST_H

#include <memory>
#include <string>
#include <vector>

#include "context_interface.h"

namespace android {
namespace init {

extern const std::string kVendorContext;

class ContextList {
  public:
    ~ContextList() {}

    void Initialize();
    void AddContext(std::unique_ptr<ContextInterface> context) {
        contexts_.emplace_back(std::move(context));
    }
    ContextInterface* GetContext(const std::string& path);
    bool ReapChild(pid_t pid);

  private:
    std::vector<std::unique_ptr<ContextInterface>> contexts_;
    std::unique_ptr<ContextInterface> init_context_;
};

}  // namespace init
}  // namespace android

#endif
