/*
 * Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <optional>
#include <string>
#include <vector>

// Find a partition by name. If no such physical partition exists, but a super
// partition exists and has a partition table for the current slot, then that
// table is searched as well.
bool PartitionExists(const std::string& name, const std::string& slot_suffix);
bool LogicalPartitionExists(const std::string& name, const std::string& slot_suffix,
                            bool* is_zero_length = nullptr);

std::optional<std::string> FindPhysicalPartition(const std::string& name);
int FlashBlockDevice(int fd, std::vector<char>& downloaded_data);
