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
#include "fastboot_driver_interface.h"

namespace fastboot {

class FastBootDriverMock : public IFBDriver {
  public:
    RetCode Reboot(std::string* response = nullptr,
                   std::vector<std::string>* info = nullptr) override;
    RetCode RebootTo(std::string target, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr) override;
};

}  // namespace fastboot