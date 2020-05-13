/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <vector>

class CompressionEngine {
  public:
    static CompressionEngine& GetInstance();

    virtual ~CompressionEngine(){};

    virtual bool Compress(const std::vector<uint8_t>& in, size_t in_size,
                          std::vector<uint8_t>& out) = 0;
    virtual bool Decompress(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) = 0;
};

class ZlibCompressionEngine : public CompressionEngine {
  public:
    bool Compress(const std::vector<uint8_t>& in, size_t in_size,
                  std::vector<uint8_t>& out) override;
    bool Decompress(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
};

class ZstdCompressionEngine : public CompressionEngine {
  public:
    bool Compress(const std::vector<uint8_t>& in, size_t in_size,
                  std::vector<uint8_t>& out) override;
    bool Decompress(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) override;
};