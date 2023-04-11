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
using testing::_;

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
    ASSERT_EQ(flash_task1->GetPartition(), partition);
    ASSERT_EQ(flash_task1->GetPartitionAndSlot(), (partition + "_" + fp->slot_override));
    ASSERT_EQ(flash_task1->GetImageName(), img_name1);
    ASSERT_EQ(flash_task1->GetSlot(), fp->slot_override);

    // task2
    ASSERT_EQ(flash_task2->GetPartition(), partition2);
    ASSERT_EQ(flash_task2->GetPartitionAndSlot(), (partition2 + "_" + fp->secondary_slot));
    ASSERT_EQ(flash_task2->GetImageName(), img_name2);
    ASSERT_EQ(flash_task2->GetSlot(), fp->secondary_slot);

    // task3
    ASSERT_EQ(flash_task3->GetPartition(), partition3);
    ASSERT_EQ(flash_task3->GetPartitionAndSlot(), (partition3 + "_" + fp->slot_override));
    ASSERT_EQ(flash_task3->GetImageName(), img_name3);
    ASSERT_EQ(flash_task3->GetSlot(), fp->slot_override);

    // task4
    ASSERT_EQ(flash_task4->GetPartition(), partition4);
    ASSERT_EQ(flash_task4->GetPartitionAndSlot(), (partition4 + "_" + fp->slot_override));
    ASSERT_EQ(flash_task4->GetImageName(), img_name4);
    ASSERT_EQ(flash_task4->GetSlot(), fp->slot_override);
}

TEST(PARSE_TEST, VERSION_CHECK_CORRRECT) {
    std::string correctversion1 = "version 1.0";
    std::string correctversion2 = "version 22.00";

    std::string badversion1 = "version";
    std::string badversion2 = "version .01";
    std::string badversion3 = "version x1";
    std::string badversion4 = "version 1.0.1";
    std::string badversion5 = "version 1.";
    std::string badversion6 = "s 1.0";
    std::string badversion7 = "version 1.0 2.0";

    ASSERT_TRUE(CheckFastbootInfoRequirements(android::base::Split(correctversion1, " ")));
    ASSERT_TRUE(CheckFastbootInfoRequirements(android::base::Split(correctversion2, " ")));

    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion1, " ")));
    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion2, " ")));
    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion3, " ")));
    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion4, " ")));
    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion5, " ")));
    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion6, " ")));
    ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(badversion7, " ")));
}
TEST(PARSE_TEST, BAD_FASTBOOT_INFO_INPUT) {
    fp->slot_override = "b";
    fp->secondary_slot = "a";
    fp->wants_wipe = true;

    std::string badcommand = "flash";
    std::string badcommand2 = "flash --slot-other --apply-vbmeta";
    std::string badcommand3 = "flash --apply-vbmeta";
    std::string badcommand4 = "if-wipe";
    std::string badcommand5 = "if-wipe flash";
    std::string badcommand6 = "reboot";
    std::string badcommand7 = "wipe dtbo";
    std::string badcommand8 = "update-super dtbo";
    std::string badcommand9 = "flash system system.img system";
    std::string badcommand10 = "reboot bootloader fastboot";
    std::string badcommand11 = "flash --slot-other --apply-vbmeta system system_other.img system";

    std::vector<std::string> vec_command1 = android::base::Split(badcommand, " ");
    std::vector<std::string> vec_command2 = android::base::Split(badcommand2, " ");
    std::vector<std::string> vec_command3 = android::base::Split(badcommand3, " ");
    std::vector<std::string> vec_command4 = android::base::Split(badcommand4, " ");
    std::vector<std::string> vec_command5 = android::base::Split(badcommand5, " ");
    std::vector<std::string> vec_command6 = android::base::Split(badcommand6, " ");
    std::vector<std::string> vec_command7 = android::base::Split(badcommand7, " ");
    std::vector<std::string> vec_command8 = android::base::Split(badcommand8, " ");
    std::vector<std::string> vec_command9 = android::base::Split(badcommand9, " ");
    std::vector<std::string> vec_command10 = android::base::Split(badcommand10, " ");
    std::vector<std::string> vec_command11 = android::base::Split(badcommand11, " ");

    std::unique_ptr<Task> task = ParseFastbootInfoLine(fp.get(), vec_command1);
    std::unique_ptr<Task> task2 = ParseFastbootInfoLine(fp.get(), vec_command2);
    std::unique_ptr<Task> task3 = ParseFastbootInfoLine(fp.get(), vec_command3);
    std::unique_ptr<Task> task4 = ParseFastbootInfoLine(fp.get(), vec_command4);
    std::unique_ptr<Task> task5 = ParseFastbootInfoLine(fp.get(), vec_command5);
    std::unique_ptr<Task> task6 = ParseFastbootInfoLine(fp.get(), vec_command6);
    std::unique_ptr<Task> task7 = ParseFastbootInfoLine(fp.get(), vec_command7);
    std::unique_ptr<Task> task8 = ParseFastbootInfoLine(fp.get(), vec_command8);
    std::unique_ptr<Task> task9 = ParseFastbootInfoLine(fp.get(), vec_command9);
    std::unique_ptr<Task> task10 = ParseFastbootInfoLine(fp.get(), vec_command10);
    std::unique_ptr<Task> task11 = ParseFastbootInfoLine(fp.get(), vec_command11);

    ASSERT_TRUE(!task && !task2 && !task3 && !task4 && !task5 && !task6 && !task7 && !task8 &&
                !task9 && !task10 && !task11);
}

TEST(PARSE_TEST, CORRECT_TASK_FORMED) {
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

    fp->wants_wipe = false;
    std::unique_ptr<Task> task6 = ParseFastbootInfoLine(fp.get(), vec_command5);

    auto _task1 = task1->AsFlashTask();
    auto _task2 = task2->AsFlashTask();
    auto _task3 = task3->AsRebootTask();
    auto _task4 = task4->AsUpdateSuperTask();
    auto _task5 = task5->AsWipeTask();

    ASSERT_TRUE(_task1 && _task2 && _task3 && _task4 && _task5 && !task6);
}

TEST(MOCK_TESTS, EXPECT_NUM_CALLS) {
    fp->slot_override = "b";
    fp->secondary_slot = "a";

    fastboot::MockFastbootDriver fb;
    fp->fb = &fb;
    EXPECT_CALL(fb, FlashPartition(_, _, _)).Times(1);

    std::string command1 = "flash dtbo";
    std::vector<std::string> vec_command1 = android::base::Split(command1, " ");
    std::unique_ptr<Task> task1 = ParseFastbootInfoLine(fp.get(), vec_command1);

    task1->Run();
}
