#include "task.h"
#include "fastboot.h"
#include "util.h"

FlashTask::FlashTask(std::string& _slot) : slot_(_slot){};

FlashTask::FlashTask(std::string& _slot, bool& _force_flash)
    : slot_(_slot), force_flash_(_force_flash) {}

void FlashTask::Run() {
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

bool FlashTask::Parse(const std::string& text) {
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
RebootTask::RebootTask(fastboot::FastBootDriver* _fb) : fb_(_fb){};

RebootTask::RebootTask(fastboot::FastBootDriver* _fb, std::string _reboot_target)
    : reboot_target_(std::move(_reboot_target)), fb_(_fb){};

void RebootTask::Run() {
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

bool RebootTask::Parse(const std::string& text) {
    std::stringstream ss(text);
    if (!ss.eof()) {
        ss >> reboot_target_;
    }
    // invalid arguments
    if (!ss.eof()) return false;
    return true;
}