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
#include "fastboot.h"

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <memory>
#include "android-base/strings.h"
using android::base::Split;

TEST(PARSE_FLASHTASK_TEST, CORRECT_FlASH_TASK_FORMED) {
    std::string command = "flash dtbo";
    std::string command2 = "flash --slot-other system system_other.img";
    std::vector<std::string> vec_command1 = android::base::Split(command, " ");
    std::vector<std::string> vec_command2 = android::base::Split(command2, " ");

    std::string partition = "dtbo";
    std::string partition2 = "system";

    std::string img_name2 = "system_other.img";

    std::unique_ptr<FlashingPlan> fp = std::make_unique<FlashingPlan>();
    fp->slot_override = "b";
    fp->secondary_slot = "a";

    std::unique_ptr<Task> task = ParseFastbootInfoLine(fp.get(), vec_command1);
    std::unique_ptr<Task> task2 = ParseFastbootInfoLine(fp.get(), vec_command2);

    auto flash_task1 = task->AsFlashTask();
    auto flash_task2 = task2->AsFlashTask();

    ASSERT_TRUE(flash_task1->GetPartition() == partition);
    ASSERT_TRUE(flash_task1->GetPartitionAndSlot() == (partition + "_" + fp->slot_override));

    ASSERT_TRUE(flash_task2->GetPartition() == partition2);
    ASSERT_TRUE(flash_task2->GetPartitionAndSlot() == (partition2 + "_" + fp->secondary_slot));
    ASSERT_TRUE(flash_task2->GetImageName() == img_name2);
    ASSERT_TRUE(flash_task2->GetSlot() == fp->secondary_slot);
}

TEST(PARSE_FLASHTASK_TEST, BAD_FASTBOOT_INFO_INPUT) {
    std::string badcommand = "flash";
    std::string badcommand2 = "flash --slot-other --apply-vbmeta";
    std::string badcommand3 = "flash --apply-vbmeta";
    std::vector<std::string> vec_command1 = android::base::Split(badcommand, " ");
    std::vector<std::string> vec_command2 = android::base::Split(badcommand2, " ");
    std::vector<std::string> vec_command3 = android::base::Split(badcommand3, " ");
    std::unique_ptr<FlashingPlan> fp = std::make_unique<FlashingPlan>();
    fp->slot_override = "b";
    fp->secondary_slot = "a";

    std::unique_ptr<Task> task = ParseFastbootInfoLine(fp.get(), vec_command1);
    std::unique_ptr<Task> task2 = ParseFastbootInfoLine(fp.get(), vec_command2);
    std::unique_ptr<Task> task3 = ParseFastbootInfoLine(fp.get(), vec_command3);

    ASSERT_TRUE(task == nullptr);
    ASSERT_TRUE(task2 == nullptr);
    ASSERT_TRUE(task3 == nullptr);
}
