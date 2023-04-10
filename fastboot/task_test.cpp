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
#include "fastboot_driver_mock.h"

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <memory>
#include "android-base/strings.h"
using android::base::Split;

std::unique_ptr<FlashingPlan> fp = std::make_unique<FlashingPlan>();

TEST(PARSE_FLASHTASK_TEST, CORRECT_FlASH_TASK_FORMED) {
    fp->slot_override = "b";
    fp->secondary_slot = "a";

    std::string command1 = "flash dtbo";
    std::string command2 = "flash --slot-other system system_other.img";
    std::string command3 = "flash system system_other.img";
    std::string command4 = "flash --apply-vbmeta vbmeta";

    std::vector<std::string> vec_command1 = android::base::Split(command1, " ");
    std::vector<std::string> vec_command2 = android::base::Split(command2, " ");
    std::vector<std::string> vec_command3 = android::base::Split(command3, " ");
    std::vector<std::string> vec_command4 = android::base::Split(command4, " ");

    // expected partitions
    std::string partition = "dtbo";
    std::string partition2 = "system";
    std::string partition3 = "system";
    std::string partition4 = "vbmeta";

    // expected images
    std::string img_name1 = "dtbo.img";
    std::string img_name2 = "system_other.img";
    std::string img_name3 = "system_other.img";
    std::string img_name4 = "vbmeta.img";

    std::unique_ptr<Task> task1 = ParseFastbootInfoLine(fp.get(), vec_command1);
    std::unique_ptr<Task> task2 = ParseFastbootInfoLine(fp.get(), vec_command2);
    std::unique_ptr<Task> task3 = ParseFastbootInfoLine(fp.get(), vec_command3);
    std::unique_ptr<Task> task4 = ParseFastbootInfoLine(fp.get(), vec_command4);

    // check all tasks are formed
    ASSERT_TRUE(task1 != nullptr && task2 != nullptr && task3 != nullptr && task4 != nullptr);

    auto flash_task1 = task1->AsFlashTask();
    auto flash_task2 = task2->AsFlashTask();
    auto flash_task3 = task3->AsFlashTask();
    auto flash_task4 = task4->AsFlashTask();

    // check all tasks are formed
    ASSERT_TRUE(flash_task1 != nullptr && flash_task2 != nullptr && flash_task3 != nullptr &&
                flash_task4 != nullptr);

    // task1
    EXPECT_EQ(flash_task1->GetPartition(), partition);
    EXPECT_EQ(flash_task1->GetPartitionAndSlot(), (partition + "_" + fp->slot_override));
    EXPECT_EQ(flash_task1->GetImageName(), img_name1);
    EXPECT_EQ(flash_task1->GetSlot(), fp->slot_override);

    // task2
    EXPECT_EQ(flash_task2->GetPartition(), partition2);
    EXPECT_EQ(flash_task2->GetPartitionAndSlot(), (partition2 + "_" + fp->secondary_slot));
    EXPECT_EQ(flash_task2->GetImageName(), img_name2);
    EXPECT_EQ(flash_task2->GetSlot(), fp->secondary_slot);

    // task3
    EXPECT_EQ(flash_task3->GetPartition(), partition3);
    EXPECT_EQ(flash_task3->GetPartitionAndSlot(), (partition3 + "_" + fp->slot_override));
    EXPECT_EQ(flash_task3->GetImageName(), img_name3);
    EXPECT_EQ(flash_task3->GetSlot(), fp->slot_override);

    // task4
    EXPECT_EQ(flash_task4->GetPartition(), partition4);
    EXPECT_EQ(flash_task4->GetPartitionAndSlot(), (partition4 + "_" + fp->slot_override));
    EXPECT_EQ(flash_task4->GetImageName(), img_name4);
    EXPECT_EQ(flash_task4->GetSlot(), fp->slot_override);
}

TEST(PARSE_FLASHTASK_TEST, BAD_FASTBOOT_INFO_INPUT) {
    fp->slot_override = "b";
    fp->secondary_slot = "a";

    std::string badcommand = "flash";
    std::string badcommand2 = "flash --slot-other --apply-vbmeta";
    std::string badcommand3 = "flash --apply-vbmeta";
    std::vector<std::string> vec_command1 = android::base::Split(badcommand, " ");
    std::vector<std::string> vec_command2 = android::base::Split(badcommand2, " ");
    std::vector<std::string> vec_command3 = android::base::Split(badcommand3, " ");

    std::unique_ptr<Task> task = ParseFastbootInfoLine(fp.get(), vec_command1);
    std::unique_ptr<Task> task2 = ParseFastbootInfoLine(fp.get(), vec_command2);
    std::unique_ptr<Task> task3 = ParseFastbootInfoLine(fp.get(), vec_command3);

    ASSERT_TRUE(!task && !task2 && !task3);
}

TEST(PARSE_FLASHTASK_TEST, CORRECT_TASK_FORMED) {
    fp->slot_override = "b";
    fp->secondary_slot = "a";
    fp->wants_wipe = true;

    std::string command1 = "flash dtbo";
    std::string command2 = "flash --slot-other system system_other.img";
    std::string command3 = "reboot bootloader";
    std::string command4 = "update-super";
    std::string command5 = "if-wipe erase cache";

    std::vector<std::string> vec_command1 = android::base::Split(command1, " ");
    std::vector<std::string> vec_command2 = android::base::Split(command2, " ");
    std::vector<std::string> vec_command3 = android::base::Split(command3, " ");
    std::vector<std::string> vec_command4 = android::base::Split(command4, " ");
    std::vector<std::string> vec_command5 = android::base::Split(command5, " ");

    std::unique_ptr<Task> task1 = ParseFastbootInfoLine(fp.get(), vec_command1);
    std::unique_ptr<Task> task2 = ParseFastbootInfoLine(fp.get(), vec_command2);
    std::unique_ptr<Task> task3 = ParseFastbootInfoLine(fp.get(), vec_command3);
    std::unique_ptr<Task> task4 = ParseFastbootInfoLine(fp.get(), vec_command4);
    std::unique_ptr<Task> task5 = ParseFastbootInfoLine(fp.get(), vec_command5);

    auto _task1 = task1->AsFlashTask();
    auto _task2 = task2->AsFlashTask();
    auto _task3 = task3->AsRebootTask();
    auto _task4 = task4->AsUpdateSuperTask();
    auto _task5 = task5->AsWipeTask();
    ASSERT_TRUE(_task1 && _task2 && _task3 && _task4 && _task5);
}

TEST(MOCK_TESTS, EXPECT_NUM_CALLS) {
    fp->slot_override = "b";
    fp->secondary_slot = "a";

    fastboot::MockFastbootDriver fb;
    EXPECT_CALL(fb, FlashPartition());
}