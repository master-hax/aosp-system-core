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

#ifndef _INIT_CONTEXT_INTERFACE_H
#define _INIT_CONTEXT_INTERFACE_H

#include <string>
#include <vector>

#include "command.h"
#include "result.h"

namespace android {
namespace init {

class ContextInterface {
  public:
    virtual ~ContextInterface() {}
    virtual Result<Success> Execute(const Command& command) = 0;
    virtual void Restart() = 0;

    virtual const std::string& path_prefix() const = 0;
    virtual const std::string& context() const = 0;
    virtual pid_t pid() const = 0;
};

}  // namespace init
}  // namespace android

#endif
