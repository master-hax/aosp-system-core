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

#include "fastboot.h"
#include "fastboot_driver.h"
#include "super_flash_helper.h"
#include "util.h"

class Task {
  public:
    Task() = default;
    virtual void Run() = 0;
    virtual ~Task() = default;
};

class FlashTask : public Task {
  public:
    FlashTask(const std::string& slot, const std::string& pname);
    FlashTask(const std::string& slot, const std::string& pname, const std::string& fname);

    void Run() override;
    ~FlashTask() {}

  private:
    const std::string pname_;
    const std::string fname_;
    const std::string slot_;
};

class RebootTask : public Task {
  public:
    RebootTask(FlashingPlan* fp);
    RebootTask(FlashingPlan* fp, const std::string& reboot_target);
    void Run() override;
    ~RebootTask() {}

  private:
    const std::string reboot_target_ = "";
    FlashingPlan* fp_;
};

class FlashSuperLayoutTask : public Task {
  public:
    FlashSuperLayoutTask(const std::string& super_name, SuperFlashHelper* helper);
    static std::unique_ptr<FlashSuperLayoutTask> Initialize(FlashingPlan* fp,
                                                            std::vector<ImageEntry>& os_images);
    using ImageEntry = std::pair<const Image*, std::string>;
    void Run() override;

  private:
    std::string super_name_;
    SuperFlashHelper* helper_ = nullptr;
};

class UpdateSuperTask : public Task {
  public:
    UpdateSuperTask(FlashingPlan* fp, const std::vector<ImageEntry>& os_images);
    void Run() override;

  private:
    FlashingPlan* fp_;
    const std::vector<ImageEntry>& os_images_;
};

class ResizeTask : public Task {
  public:
    ResizeTask(FlashingPlan* fp, const std::string& pname, const std::string& size,
               const std::string& slot);
    void Run() override;

  private:
    FlashingPlan* fp_;
    const std::string pname_;
    const std::string size_;
    const std::string slot_;
};

class DeleteTask : public Task {
  public:
    DeleteTask(FlashingPlan* _fp, const std::string& _pname);
    void Run() override;

  private:
    FlashingPlan* fp_;
    const std::string pname_;
};
