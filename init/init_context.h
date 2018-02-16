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

#ifndef _INIT_INIT_CONTEXT_H
#define _INIT_INIT_CONTEXT_H

#include <string>
#include <vector>

#include "command.h"
#include "context_interface.h"
#include "result.h"

namespace android {
namespace init {

class InitContext : public ContextInterface {
  public:
    virtual ~InitContext() {}
    Result<Success> Execute(const Command& command) override;
    void Restart() override {}

    const std::string& path_prefix() const override {
        static const std::string default_path = "*";
        return default_path;
    }
    const std::string& context() const override { return kInitContext; }
    pid_t pid() const override { return 1; }

    static const std::string kInitContext;
};

}  // namespace init
}  // namespace android

#endif
