/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _INIT_COMMAND_H
#define _INIT_COMMAND_H

#include <functional>
#include <string>
#include <vector>

#include "builtin_arguments.h"
#include "builtins.h"
#include "result.h"

namespace android {
namespace init {

struct Command {
    Command(BuiltinFunction f, bool execute_in_subcontext, const std::vector<std::string>& args,
            int line)
        : func(std::move(f)), execute_in_subcontext(execute_in_subcontext), args(args), line(line) {}

    const BuiltinFunction func;
    const bool execute_in_subcontext;
    const std::vector<std::string> args;
    const int line;
};

}  // namespace init
}  // namespace android

#endif
