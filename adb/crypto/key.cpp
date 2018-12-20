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

#include "key.h"

#include "ec_key.h"

Key::Key(const std::string& name, uint32_t bits) : name_(name), bits_(bits) {
}

std::unique_ptr<Key> createKey(KeyType type,
                               const std::string& name,
                               const char* data) {
    switch (type) {
        case KeyType::EllipticCurve:
            return std::make_unique<EllipticCurveKey>(name, data);
            break;
    }
    return nullptr;
}
