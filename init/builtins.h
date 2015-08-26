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

#ifndef _INIT_BUILTINS_H
#define _INIT_BUILTINS_H

#include <map>
#include <string>
#include <vector>

using BuiltinFunction = int (*) (const std::vector<std::string>& args);
using BuiltinFunctionInfo = std::tuple<std::size_t, std::size_t, BuiltinFunction>;
const BuiltinFunctionInfo* FindBuiltinFunctionInfo(const std::string& keyword);

#endif
