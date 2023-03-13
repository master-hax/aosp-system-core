//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include <cstdint>
#include <limits>

class IFBDriver {
  public:
    static constexpr int RESP_TIMEOUT = 30;  // 30 seconds
    static constexpr uint32_t MAX_DOWNLOAD_SIZE = std::numeric_limits<uint32_t>::max();
    static constexpr size_t TRANSPORT_CHUNK_SIZE = 1024;
};