/*
 * Copyright 2022, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <regex>
#include <string>
#include <vector>

namespace dmesg_parser {

class DmesgParser {
  public:
    DmesgParser();
    void processLine(const std::string& line);
    bool reportReady() const;
    std::string reportType() const;
    std::string reportTitle() const;
    std::string flushReport();

  private:
    std::string stripSensitiveData(const std::string& line) const;

    const std::string kTimestampRe = "^\\[[^\\]]+\\]\\s";
    const std::string kRegisterRe = "([ _][Rx]..|raw): [0-9a-f]{16}";
    const std::string kAddr64Re = "\\b(?:0x)?[0-9a-f]{16}\\b";
    const std::vector<std::string> kBugTypes = {"KFENCE", "KASAN"};
    const std::vector<std::string> kSkipSubstrings = {"Comm: ", "Hardware name: "};
    const std::vector<std::string> kCutInfix = {"Corrupted memory at ", " by task "};

    bool report_ready;
    std::string last_report;
    std::regex bug_pattern, register_pattern, addr64_pattern;
    std::regex task_line_pattern, task_delimiter_pattern;
    std::string current_report;
    std::string current_task, current_tool, current_title;
};

}  // namespace dmesg_parser
