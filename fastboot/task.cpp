#include "task.h"

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