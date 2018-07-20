/*
 * Copyright (C) 2018 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#pragma once

#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fastboot {
namespace extension {

struct Configuration {
    struct GetVar {
        std::string regex_str;
        std::regex regex;
        int line_num;
    };
    struct PartitionInfo {
        enum TestConfig { NO = 0, NO_WRITES, YES };
        bool slots;  // Does it have slots
        TestConfig test;
    };

    struct CommandTest {
        enum Expect { OKAY = 0, FAIL, DATA };
        std::string name;
        int line_num;
        std::string arg;
        Expect expect;
        std::string regex_str;
        std::regex regex;
        std::string input;
        std::string output;
        std::string validator;
    };

    struct OemCommand {
        bool restricted;  // Does device need to be unlocked?
        std::vector<CommandTest> tests;
    };

    std::unordered_map<std::string, GetVar> getvars;
    std::unordered_map<std::string, PartitionInfo> partitions;
    std::unordered_map<std::string, OemCommand> oem;
    std::string checksum;
};

bool ParseXml(const std::string& file, Configuration* config);

}  // namespace extension
}  // namespace fastboot
