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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex>

#include <cstdlib>
#include <fstream>
#include <random>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "extensions.h"
#include "tinyxml2.h"

namespace fastboot {

struct Configuration {
    struct PartitionInfo {
        enum TestConfig { NO = 0, NO_WRITES, YES };

        bool slots;  // Does it have slots
        TestConfig test;
    };
    std::unordered_map<std::string, std::regex> getvars;
    std::unordered_map<std::string, PartitionInfo> partitions;
};

bool XMLAssert(bool cond, const tinyxml2::XMLElement* elem, const char* msg) {
    if (!cond) {
        printf("%s (line %d)\n", msg, elem->GetLineNum());
    }

    return !cond;
}

void ParseXml(const std::string& file) {
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(file.c_str())) {
        printf("Failed to load file: %s\n", doc.ErrorStr());
        return;
    }

    // We store all stuff parsed from the XML in here
    Configuration config;

    tinyxml2::XMLConstHandle handle(&doc);
    tinyxml2::XMLConstHandle root(handle.FirstChildElement("config"));
    // Extract getvars
    const tinyxml2::XMLElement* var =
            root.FirstChildElement("getvar").FirstChildElement("var").ToElement();
    while (var) {
        const std::string key(var->Attribute("key"));
        const std::string reg(var->Attribute("assert"));
        if (XMLAssert(key.size(), var, "The var key name is empty")) return;
        // TODO, is there a way to make sure regex is valid without exceptions?
        if (XMLAssert(config.getvars.find(key) == config.getvars.end(), var,
                      "The same getvar variable name is listed twice"))
            return;
        std::regex regex(reg, std::regex::extended);
        config.getvars[key] = std::move(regex);
        var = var->NextSiblingElement("var");
    }

    // Extract partitions
    const tinyxml2::XMLElement* part =
            root.FirstChildElement("partitions").FirstChildElement("part").ToElement();
    while (part) {
        const std::string name(part->Attribute("value"));
        const std::string slots(part->Attribute("slots"));
        const std::string test(part->Attribute("test"));
        if (XMLAssert(name.size(), part, "The name of a partition can not be empty")) return;
        if (XMLAssert(slots == "yes" || slots == "no", part,
                      "Slots attribute must be 'yes' or 'no'"))
            return;
        bool allowed = test == "yes" || test == "no-writes" || test == "no";
        if (XMLAssert(allowed, part, "The test attribute must be 'yes' 'no-writes' or 'no'"))
            return;
        if (XMLAssert(config.partitions.find(name) == config.partitions.end(), part,
                      "The same partition name is listed twice"))
            return;
        Configuration::PartitionInfo part_info;
        part_info.test = (test == "yes")
                                 ? Configuration::PartitionInfo::YES
                                 : (test == "no-writes") ? Configuration::PartitionInfo::NO_WRITES
                                                         : Configuration::PartitionInfo::NO;
        part_info.slots = slots == "yes";
        config.partitions[name] = part_info;
        part = part->NextSiblingElement("part");
    }

    // Extract oem commands
    const tinyxml2::XMLElement* command =
            root.FirstChildElement("oem").FirstChildElement("command").ToElement();
    while (part) {
        command = command->NextSiblingElement("command");
    }
}

}  // namespace fastboot
