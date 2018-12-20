/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#pragma once

#include "key_type.h"

#include <stdint.h>
#include <string>

class Key {
public:
    virtual ~Key() = default;

    Key(const std::string& name, uint32_t bits);

    virtual KeyType type() const = 0;
    const std::string& name() const { return name_; }
    uint32_t bits() const { return bits_; }

    virtual const char* c_str() const = 0;
    virtual size_t size() const = 0;

private:
    std::string name_;
    uint32_t bits_;
};

std::unique_ptr<Key> createKey(KeyType type,
                               const std::string& name,
                               const char* data);

