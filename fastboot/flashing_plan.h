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

#include <string>
#include "fastboot_driver.h"
#include "util.h"

enum class ImageType {
    // Must be flashed for device to boot into the kernel.
    BootCritical,
    // Normal partition to be flashed during "flashall".
    Normal,
    // Partition that is never flashed during "flashall".
    Extra
};

struct Image {
    std::string nickname;
    std::string img_name;
    std::string sig_name;
    std::string part_name;
    bool optional_if_no_image;
    ImageType type;
    bool IsSecondary() const { return nickname.empty(); }
};

using ImageEntry = std::pair<const Image*, std::string>;

struct FlashingPlan {
    unsigned fs_options = 0;
    // If the image uses the default slot, or the user specified "all", then
    // the paired string will be empty. If the image requests a specific slot
    // (for example, system_other) it is specified instead.
    ImageSource* source;
    bool wants_resize_logical_partitions = false;
    bool wants_wipe = false;
    bool skip_reboot = false;
    bool wants_set_active = false;
    bool skip_secondary = false;
    bool force_flash = false;

    std::string slot_override;
    std::string secondary_slot;

    fastboot::FastBootDriver* fb;
};

class Task;
class FlashTask;
class RebootTask;
class UpdateSuperTask;
class WipeTask;
class ResizeTask;
class FlashSuperLayoutTask;