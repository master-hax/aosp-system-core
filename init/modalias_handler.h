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

#ifndef _INIT_MODALIAS_HANDLER_H
#define _INIT_MODALIAS_HANDLER_H

#include "result.h"
#include "uevent.h"

#include <map>
#include <string>
#include <vector>

namespace android {
namespace init {

class ModaliasHandler {
  public:
    ModaliasHandler();
    ~ModaliasHandler(){};

    void HandleModaliasEvent(const Uevent& uevent);

  private:
    bool ProcessModaliasEvent(const Uevent& uevent);
    int insmodWithDeps(std::string module_name, std::string args);
    int insmod(std::string path_name, std::string args);

    Result<Success> parseDepCallback(std::vector<std::string>&& args);
    Result<Success> parseAliasCallback(std::vector<std::string>&& args);

    std::vector<std::pair<std::string, std::string>> module_aliases;
    std::map<std::string, std::vector<std::string>> module_deps;
};

}  // namespace init
}  // namespace android

#endif
