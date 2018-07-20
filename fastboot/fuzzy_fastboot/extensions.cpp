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

#include <csignal>
#include <cstdlib>
#include <fstream>

#include "extensions.h"
#include "tinyxml2.h"

namespace fastboot {
namespace extension {

namespace {  // private to this file

const std::unordered_map<std::string, Configuration::CommandTest::Expect> CMD_EXPECTS = {
        {"okay", Configuration::CommandTest::OKAY},
        {"fail", Configuration::CommandTest::FAIL},
};

bool XMLAssert(bool cond, const tinyxml2::XMLElement* elem, const char* msg) {
    if (!cond) {
        printf("%s (line %d)\n", msg, elem->GetLineNum());
    }
    return !cond;
}

const std::string XMLAttribute(const tinyxml2::XMLElement* elem, const std::string key,
                               const std::string key_default = "") {
    if (!elem->Attribute(key.c_str())) {
        return key_default;
    }

    return elem->Attribute(key.c_str());
}

bool ExtractPartitions(tinyxml2::XMLConstHandle handle, Configuration* config) {
    // Extract partitions
    const tinyxml2::XMLElement* part = handle.FirstChildElement("part").ToElement();
    while (part) {
        const std::string name = XMLAttribute(part, "value");
        const std::string slots = XMLAttribute(part, "slots");
        const std::string test = XMLAttribute(part, "test");
        const std::string hashable = XMLAttribute(part, "hashable");
        if (XMLAssert(!name.empty(), part, "The name of a partition can not be empty"))
            return false;
        if (XMLAssert(slots == "yes" || slots == "no", part,
                      "Slots attribute must be 'yes' or 'no'"))
            return false;

        if (XMLAssert(hashable == "" || hashable == "yes" || hashable == "no", part,
                      "Hashable attribute must be 'yes' or 'no'"))
            return false;
        bool allowed = test == "yes" || test == "no-writes" || test == "no";
        if (XMLAssert(allowed, part, "The test attribute must be 'yes' 'no-writes' or 'no'"))
            return false;
        if (XMLAssert(config->partitions.find(name) == config->partitions.end(), part,
                      "The same partition name is listed twice"))
            return false;
        Configuration::PartitionInfo part_info;
        part_info.test = (test == "yes")
                                 ? Configuration::PartitionInfo::YES
                                 : (test == "no-writes") ? Configuration::PartitionInfo::NO_WRITES
                                                         : Configuration::PartitionInfo::NO;
        part_info.hashable = (hashable == "yes" || hashable == "");  // default to yes
        part_info.slots = slots == "yes";
        config->partitions[name] = part_info;
        part = part->NextSiblingElement("part");
    }
    return true;
}

bool ExtractGetVars(tinyxml2::XMLConstHandle handle, Configuration* config) {
    // Extract getvars
    const tinyxml2::XMLElement* var = handle.FirstChildElement("var").ToElement();
    while (var) {
        const std::string key = XMLAttribute(var, "key");
        const std::string reg = XMLAttribute(var, "assert");
        if (XMLAssert(key.size(), var, "The var key name is empty")) return false;
        // TODO, is there a way to make sure regex is valid without exceptions?
        if (XMLAssert(config->getvars.find(key) == config->getvars.end(), var,
                      "The same getvar variable name is listed twice"))
            return false;
        Configuration::GetVar getvar{reg, std::regex(reg, std::regex::extended), var->GetLineNum()};
        config->getvars[key] = std::move(getvar);
        var = var->NextSiblingElement("var");
    }
    return true;
}

bool ExtractOem(tinyxml2::XMLConstHandle handle, Configuration* config) {
    // Extract getvars
    // Extract oem commands
    const tinyxml2::XMLElement* command = handle.FirstChildElement("command").ToElement();
    while (command) {
        const std::string cmd = XMLAttribute(command, "value");
        const std::string permissions = XMLAttribute(command, "permissions");
        if (XMLAssert(cmd.size(), command, "Empty command value")) return false;
        if (XMLAssert(permissions == "none" || permissions == "unlocked", command,
                      "Permissions attribute must be 'none' or 'unlocked'"))
            return false;

        // Each command has tests
        std::vector<Configuration::CommandTest> tests;
        const tinyxml2::XMLElement* test = command->FirstChildElement("test");
        while (test) {  // iterate through tests
            Configuration::CommandTest ctest;

            ctest.line_num = test->GetLineNum();
            const std::string default_name = "XMLTest-line-" + std::to_string(test->GetLineNum());
            ctest.name = XMLAttribute(test, "name", default_name);
            ctest.arg = XMLAttribute(test, "value");
            ctest.input = XMLAttribute(test, "input");
            ctest.output = XMLAttribute(test, "output");
            ctest.validator = XMLAttribute(test, "validate");
            ctest.regex_str = XMLAttribute(test, "assert");

            const std::string expect = XMLAttribute(test, "expect");

            if (XMLAssert(CMD_EXPECTS.find(expect) != CMD_EXPECTS.end(), test,
                          "Expect attribute must be 'okay' or 'fail'"))
                return false;
            ctest.expect = CMD_EXPECTS.at(expect);
            std::regex regex;
            if (expect == "okay" && ctest.regex_str.size()) {
                ctest.regex = std::regex(ctest.regex_str, std::regex::extended);
            }
            tests.push_back(std::move(ctest));
            test = test->NextSiblingElement("test");
        }

        // Build the command struct
        const Configuration::OemCommand oem_cmd{permissions == "unlocked", std::move(tests)};
        config->oem[cmd] = std::move(oem_cmd);

        command = command->NextSiblingElement("command");
    }
    return true;
}

bool ExtractChecksum(tinyxml2::XMLConstHandle handle, Configuration* config) {
    const tinyxml2::XMLElement* checksum = handle.ToElement();
    if (checksum && checksum->Attribute("value")) {
        config->checksum = XMLAttribute(checksum, "value");
        config->checksum_parser = XMLAttribute(checksum, "parser");
        if (XMLAssert(config->checksum_parser != "", checksum,
                      "A checksum parser attribute is mandatory"))
            return false;
    }
    return true;
}

}  // anonymous namespace

bool ParseXml(const std::string& file, Configuration* config) {
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(file.c_str())) {
        printf("Failed to open/parse XML file '%s'\nXMLError: %s\n", file.c_str(), doc.ErrorStr());
        return false;
    }

    tinyxml2::XMLConstHandle handle(&doc);
    tinyxml2::XMLConstHandle root(handle.FirstChildElement("config"));

    // Extract the getvars
    if (!ExtractGetVars(root.FirstChildElement("getvar"), config)) {
        return false;
    }
    // Extract the partition info
    if (!ExtractPartitions(root.FirstChildElement("partitions"), config)) {
        return false;
    }

    // Extract oem commands
    if (!ExtractOem(root.FirstChildElement("oem"), config)) {
        return false;
    }

    // Extract checksum
    if (!ExtractChecksum(root.FirstChildElement("checksum"), config)) {
        return false;
    }

    return true;
}

}  // namespace extension
}  // namespace fastboot
