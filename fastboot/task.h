//
// Copyright (C) 2020 The Android Open Source Project
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
#pragma once

#include <sstream>
#include <string>

#include "fastboot_driver.h"

class Task {
  public:
    Task() = default;
    virtual void Run() = 0;
    virtual bool Parse(const std::string& text) = 0;
    virtual ~Task() = default;
};

class FlashTask : public Task {
  public:
    FlashTask(const std::string& _slot);
    FlashTask(const std::string& _slot, bool _force_flash);
    FlashTask(const std::string& _slot, bool _force_flash, const std::string& _pname,
              const std::string& _fname);

    void Run() override;
    bool Parse(const std::string& text);
    ~FlashTask() {}

  private:
    std::string pname_;
    std::string fname_;
    std::string slot_;
    bool force_flash_ = false;
};

class RebootTask : public Task {
  public:
    RebootTask(fastboot::FastBootDriver* _fb);
    RebootTask(fastboot::FastBootDriver* _fb, std::string _reboot_target);
    void Run() override;
    bool Parse(const std::string& text) override;
    ~RebootTask() {}

  private:
    std::string reboot_target_ = "";
    fastboot::FastBootDriver* fb_;
};