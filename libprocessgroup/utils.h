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

#pragma once

#include <string>

bool MkdirAndChown(const std::string& path, mode_t mode, uid_t uid, gid_t gid);
int GetTokens(char* str, const std::string& delim, char* tokens[], int tok_count);
void ReplaceAll(std::string& str, const std::string& from, const std::string& to);
bool IsAppDependentPath(const std::string& path);
std::string ExpandAppDependentPath(const std::string& cg_path, const std::string& subgrp, uid_t uid,
                                   pid_t pid);
bool Chown(const std::string& path, uid_t uid, gid_t gid);
int GetTid();
void set_timerslack_ns(bool timerslack_support, int tid, unsigned long slack);
int add_tid_to_cgroup(int tid, int fd);
