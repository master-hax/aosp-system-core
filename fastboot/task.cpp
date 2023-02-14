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
#include "task.h"
#include <iostream>
#include "fastboot.h"
#include "filesystem.h"
#include "super_flash_helper.h"

FlashTask::FlashTask(const std::string& _slot) : slot_(_slot){};
FlashTask::FlashTask(const std::string& _slot, bool _force_flash)
    : slot_(_slot), force_flash_(_force_flash) {}
FlashTask::FlashTask(const std::string& _slot, bool _force_flash, const std::string& _pname)
    : pname_(_pname), fname_(find_item(_pname)), slot_(_slot), force_flash_(_force_flash) {
    if (fname_.empty()) die("cannot determine image filename for '%s'", pname_.c_str());
}
FlashTask::FlashTask(const std::string& _slot, bool _force_flash, const std::string& _pname,
                     const std::string& _fname)
    : pname_(_pname), fname_(_fname), slot_(_slot), force_flash_(_force_flash) {}

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

FlashSuperLayoutTask::FlashSuperLayoutTask(std::shared_ptr<FlashingPlan> flashing_plan)
    : flashing_plan_(flashing_plan) {}

void FlashSuperLayoutTask::Run() {
    std::vector<SparsePtr> files;
    if (int limit = get_sparse_limit(sparse_file_len(flashing_plan_->s_.get(), false, false))) {
        files = resparse_file(flashing_plan_->s_.get(), limit);
    } else {
        files.emplace_back(std::move(flashing_plan_->s_));
    }

    // Send the data to the device.
    flash_partition_files(flashing_plan_->super_name_, files);

    // Remove images that we already flashed, just in case we have non-dynamic OS images.
    auto remove_if_callback = [&, this](const ImageEntry& entry) -> bool {
        return flashing_plan_->helper_.WillFlash(GetPartitionName(entry, flashing_plan_->slot_));
    };
    flashing_plan_->os_images_.erase(
            std::remove_if(flashing_plan_->os_images_.begin(), flashing_plan_->os_images_.end(),
                           remove_if_callback),
            flashing_plan_->os_images_.end());
}
bool FlashSuperLayoutTask::Initialize() {

    if (!supports_AB()) {
        LOG(VERBOSE) << "Cannot optimize flashing super on non-AB device";
        return false;
    }
    if (flashing_plan_->slot_ == "all") {
        LOG(VERBOSE) << "Cannot optimize flashing super for all slots";
        return false;
    }

    // Does this device use dynamic partitions at all?
    unique_fd fd = flashing_plan_->source_.OpenFile("super_empty.img");
    if (fd < 0) {
        LOG(VERBOSE) << "could not open super_empty.img";
        return false;
    }

    // Try to find whether there is a super partition.
    if (flashing_plan_->fb_->GetVar("super-partition-name", &flashing_plan_->super_name_) !=
        fastboot::SUCCESS) {
        flashing_plan_->super_name_ = "super";
    }
    std::string partition_size_str;
    if (flashing_plan_->fb_->GetVar("partition-size:" + flashing_plan_->super_name_,
                                    &partition_size_str) != fastboot::SUCCESS) {
        LOG(VERBOSE) << "Cannot optimize super flashing: could not determine super partition";
        return false;
    }

    if (!flashing_plan_->helper_.Open(fd)) {
        return false;
    }

    for (const auto& entry : flashing_plan_->os_images_) {
        auto partition = GetPartitionName(entry, flashing_plan_->slot_);
        auto image = entry.first;

        if (!flashing_plan_->helper_.AddPartition(partition, image->img_name,
                                                  image->optional_if_no_image)) {
            return false;
        }
    }
    flashing_plan_->s_ = flashing_plan_->helper_.GetSparseLayout();

    if (!flashing_plan_->s_) {
        return false;
    }
    return true;
}