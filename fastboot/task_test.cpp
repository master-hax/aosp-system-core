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

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>

TEST(FlASH_TEST, CORRECT_PARTITION_NAME) {
    std::string partition = "system";
    std::string slot = "a";
    std::string filename = "system.img";
    bool apply_vbmeta = false;

    FlashTask task(slot, partition, filename, apply_vbmeta);
}

TEST(PARSE_TEST, CORRECT_TASK_TYPE) {
    std::string flash = "flash dtbo";
    std::ifstream fs(flash);

    std::ofstream tmp;
    tmp.open("myfile.txt", std::ios::out | std::ios::binary);
}