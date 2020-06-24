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

#include <memory>

class CompressionEngine {
  public:
    static CompressionEngine& GetInstance();

    virtual ~CompressionEngine(){};

    virtual bool Compress(uint8_t* in, size_t in_size, std::unique_ptr<uint8_t[]>& out,
                          size_t& out_size) = 0;
    // Decompress the contents of `in` into `out`.  `out_size` must be set to the decompressed size
    // of the contents.
    virtual bool Decompress(uint8_t* in, size_t in_size, std::unique_ptr<uint8_t[]>& out,
                            size_t out_size) = 0;
};

class ZlibCompressionEngine : public CompressionEngine {
  public:
    bool Compress(uint8_t* in, size_t in_size, std::unique_ptr<uint8_t[]>& out,
                  size_t& out_size) override;
    bool Decompress(uint8_t* in, size_t in_size, std::unique_ptr<uint8_t[]>& out,
                    size_t out_size) override;
};

class ZstdCompressionEngine : public CompressionEngine {
  public:
    bool Compress(uint8_t* in, size_t in_size, std::unique_ptr<uint8_t[]>& out,
                  size_t& out_size) override;
    bool Decompress(uint8_t* in, size_t in_size, std::unique_ptr<uint8_t[]>& out,
                    size_t out_size) override;
};