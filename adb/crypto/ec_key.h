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

#include "key.h"

class EllipticCurveKey : public Key {
public:
    EllipticCurveKey(const std::string& name, const char* data);

    KeyType type() const override { return KeyType::EllipticCurve; }

    const char* c_str() const { return data_.c_str(); }
    size_t size() const { return data_.size(); }
private:
    std::string data_;
};
