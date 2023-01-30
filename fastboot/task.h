/*
 * Copyright (C) 2018 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#pragma once
#include <string>

class Task {
  public:
    Task() = default;
    virtual void Run() = 0;
    virtual bool Parse(std::string& text) = 0;
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
    bool Parse(std::string& text) override {
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

class RebootTask : public Task {
  public:
    RebootTask(fastboot::FastBootDriver* _fb) : fb_(_fb){};
    RebootTask(fastboot::FastBootDriver* _fb, std::string _reboot_target)
        : reboot_target_(_reboot_target), fb_(_fb){};
    void Run() override {
        if ((reboot_target_ == "userspace" || reboot_target_ == "fastboot")) {
            if (!is_userspace_fastboot()) {
                reboot_to_userspace_fastboot();
                fb_->WaitForDisconnect();
            }
        } else if (reboot_target_ == "recovery") {
            fb_->RebootTo("recovery");
            fb_->WaitForDisconnect();
        } else if (reboot_target_ == "bootloader") {
            fb_->RebootTo("bootloader");
            fb_->WaitForDisconnect();
        } else if (reboot_target_ == "") {
            fb_->Reboot();
            fb_->WaitForDisconnect();
        } else {
            syntax_error("unknown reboot target %s", reboot_target_.c_str());
        }
    }
    bool Parse(std::string& text) override {
        std::stringstream ss(text);
        if (!ss.eof()) {
            ss >> reboot_target_;
        }
        // invalid arguments
        if (!ss.eof()) return false;
        return true;
    }
    ~RebootTask() {}

  private:
    std::string reboot_target_ = "";
    fastboot::FastBootDriver* fb_;
};