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

#include "init_context.h"

#include "builtin_arguments.h"

#include "util.h"

namespace android {
namespace init {

const std::string InitContext::kInitContext = "u:r:init:s0";

Result<Success> InitContext::Execute(const Command& command) {
    auto builtin_arguments = BuiltinArguments(context());

    builtin_arguments.args.resize(command.args.size());
    builtin_arguments.args[0] = command.args[0];
    for (std::size_t i = 1; i < command.args.size(); ++i) {
        if (!expand_props(command.args[i], &builtin_arguments.args[i])) {
            return Error() << "cannot expand '" << command.args[i] << "'";
        }
    }

    return command.func(builtin_arguments);
}

}  // namespace init
}  // namespace android
