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
#include "util.h"

class Task {
  public:
    Task() = default;
    virtual void Run() = 0;
    virtual bool Parse(const std::string& text) = 0;
    virtual ~Task() = default;
};

class FlashTask : public Task {
  public:
    FlashTask(std::string& _slot) : slot_(_slot) {}
    FlashTask(std::string& _slot, bool& _force_flash) : slot_(_slot), force_flash_(_force_flash) {}

    void Run() override {
        auto flash = [&](const std::string& partition) {
            if (should_flash_in_userspace(partition) && !is_userspace_fastboot() && !force_flash_) {
                die("The partition you are trying to flash is dynamic, and "
                    "should be flashed via fastbootd. Please run:\n"
                    "\n"
                    "    fastboot reboot fastboot\n"
                    "\n"
                    "And try again. If you are intentionally trying to "
                    "overwrite a fixed partition, use --force.");
            }
            do_flash(partition.c_str(), fname_.c_str());
        };
        do_for_partitions(pname_, slot_, flash, true);
    }
    bool Parse(const std::string& text) override {
        std::stringstream ss(text);
        ss >> pname_;
        if (!ss.eof()) {
            ss >> fname_;
        } else {
            fname_ = find_item(pname_);
            if (fname_.empty()) die("cannot determine image filename for '%s'", pname_.c_str());
        }
        return true;
    }
    ~FlashTask() {}

  private:
    std::string pname_;
    std::string fname_;
    std::string slot_;
    bool force_flash_ = false;
};
