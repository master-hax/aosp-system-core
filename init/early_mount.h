/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _INIT_EARLY_MOUNT_H
#define _INIT_EARLY_MOUNT_H

#include <string>

const std::string kAndroidDtDir("/proc/device-tree/firmware/android/");

bool is_dt_value_expected(const std::string& dt_file_suffix, const std::string& expected_value);

bool early_mount();

// Invokes setenv("INIT_AVB_VERSION", avb_version) in init first stage under recovery.
void set_init_avb_version_in_recovery();

#endif
