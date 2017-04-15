/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _INIT_UEVENTD_H_
#define _INIT_UEVENTD_H_

#include <string>
#include <vector>

#include "init_parser.h"

int ueventd_main(int argc, char** argv);

struct Subsystem {
    enum class DevnameSource {
        DEVNAME_UEVENT_DEVNAME,
        DEVNAME_UEVENT_DEVPATH,
    };

    bool operator==(const std::string& string_name) { return name == string_name; }

    std::string name;
    std::string dir_name;
    DevnameSource devname_source;
};

class SubsystemParser : public SectionParser {
  public:
    SubsystemParser() {}
    bool ParseSection(const std::vector<std::string>& args, std::string* err) override;
    bool ParseLineSection(const std::vector<std::string>& args, const std::string& filename,
                          int line, std::string* err) override;
    void EndSection() override;
    void EndFile(const std::string&) override {}

  private:
    Subsystem subsystem_;
};

extern std::vector<Subsystem> subsystems;

#endif
