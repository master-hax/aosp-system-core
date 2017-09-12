/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_SUBCONTEXT_H
#define _INIT_SUBCONTEXT_H

#include <string>
#include <vector>

#include <android-base/unique_fd.h>

#include "builtins.h"

namespace android {
namespace init {

extern const KeywordFunctionMap* subcontext_function_map;

class Subcontext {
  public:
    Subcontext(std::string path_prefix, std::string context)
        : path_prefix_(path_prefix), context_(std::move(context)) {
        Fork();
    }
    ~Subcontext();

    Subcontext(Subcontext&& other) {
        path_prefix_ = std::move(other.path_prefix_);
        context_ = std::move(other.context_);
        pid_ = other.pid_;
        other.pid_ = 0;
        socket_ = std::move(other.socket_);
    }
    Subcontext& operator=(Subcontext&& other) {
        path_prefix_ = std::move(other.path_prefix_);
        context_ = std::move(other.context_);
        pid_ = other.pid_;
        other.pid_ = 0;
        socket_ = std::move(other.socket_);
        return *this;
    }

    Result<Success> Execute(const std::vector<std::string>& command);
    void Restart();

    const std::string& path_prefix() const { return path_prefix_; }
    const std::string& context() const { return context_; }
    pid_t pid() const { return pid_; }

  private:
    void Fork();

    std::string path_prefix_;
    std::string context_;
    pid_t pid_;
    android::base::unique_fd socket_;
};

std::vector<Subcontext>* InitializeSubcontexts();
bool SubcontextChildReap(pid_t pid);

}  // namespace init
}  // namespace android

#endif
