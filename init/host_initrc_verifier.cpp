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

#include <pwd.h>

#include <android-base/logging.h>

#include "action.h"
#include "builtins.h"
#include "init_parser.h"
#include "service.h"

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StderrLogger);

    if (argc != 2) {
        LOG(ERROR) << "Usage: " << argv[0] << " <init file to parse>";
        return -1;
    }

    const BuiltinFunctionMap function_map;
    Action::set_function_map(&function_map);

    Parser& parser = Parser::GetInstance();
    parser.AddSectionParser("service", std::make_unique<ServiceParser>());
    parser.AddSectionParser("on", std::make_unique<ActionParser>());

    auto result = parser.ParseConfig(argv[1]);
    LOG(ERROR) << (result ? "Parser Success!" : "Parser Error");
    return result ? 0 : -1;
}

// Below are a list of libinit and a few other functions that we don't have host symbols for nor
// need.

// from libbase
namespace android {
namespace base {

std::string GetProperty(const std::string&, const std::string& default_value) {
    return default_value;
}
}
}

// from property_service.cpp

uint32_t property_set(const std::string&, const std::string&) {
    return 0;
}

bool is_legal_property_name(const std::string& name) {
    size_t namelen = name.size();

    if (namelen < 1) return false;
    if (name[0] == '.') return false;
    if (name[namelen - 1] == '.') return false;

    /* Only allow alphanumeric, plus '.', '-', '@', or '_' */
    /* Don't allow ".." to appear in a property name */
    for (size_t i = 0; i < namelen; i++) {
        if (name[i] == '.') {
            // i=0 is guaranteed to never have a dot. See above.
            if (name[i - 1] == '.') return false;
            continue;
        }
        if (name[i] == '_' || name[i] == '-' || name[i] == '@') continue;
        if (name[i] >= 'a' && name[i] <= 'z') continue;
        if (name[i] >= 'A' && name[i] <= 'Z') continue;
        if (name[i] >= '0' && name[i] <= '9') continue;
        return false;
    }

    return true;
}

// from capabilities.cpp

int LookupCap(const std::string&) {
    return -1;
}

bool CapAmbientSupported() {
    return false;
}

unsigned int GetLastValidCap() {
    return 0;
}

bool SetCapsForExec(const CapSet&) {
    return false;
}

// from init.cpp

std::string default_console;
struct selabel_handle* sehandle;
const char* ENV[32];

int add_environment(const char*, const char*) {
    return 0;
}

// from libcutils

int android_set_ioprio(int, IoSchedClass, int) {
    return 0;
}

// from libselinux

int selinux_android_restorecon(const char*, unsigned int) {
    return 0;
}

// from reboot.cpp

void DoReboot(unsigned int, const std::string&, const std::string&, bool) {}

// from builtins.cpp

static int do_dummy(const std::vector<std::string>&) {
    return 0;
}

BuiltinFunctionMap::Map& BuiltinFunctionMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    // clang-format off
    static const Map builtin_functions = {
        {"bootchart",               {1,     1,    do_dummy}},
        {"chmod",                   {2,     2,    do_dummy}},
        {"chown",                   {2,     3,    do_dummy}},
        {"class_reset",             {1,     1,    do_dummy}},
        {"class_restart",           {1,     1,    do_dummy}},
        {"class_start",             {1,     1,    do_dummy}},
        {"class_stop",              {1,     1,    do_dummy}},
        {"copy",                    {2,     2,    do_dummy}},
        {"domainname",              {1,     1,    do_dummy}},
        {"enable",                  {1,     1,    do_dummy}},
        {"exec",                    {1,     kMax, do_dummy}},
        {"exec_start",              {1,     1,    do_dummy}},
        {"export",                  {2,     2,    do_dummy}},
        {"hostname",                {1,     1,    do_dummy}},
        {"ifup",                    {1,     1,    do_dummy}},
        {"init_user0",              {0,     0,    do_dummy}},
        {"insmod",                  {1,     kMax, do_dummy}},
        {"installkey",              {1,     1,    do_dummy}},
        {"load_persist_props",      {0,     0,    do_dummy}},
        {"load_system_props",       {0,     0,    do_dummy}},
        {"loglevel",                {1,     1,    do_dummy}},
        {"mkdir",                   {1,     4,    do_dummy}},
        {"mount_all",               {1,     kMax, do_dummy}},
        {"mount",                   {3,     kMax, do_dummy}},
        {"umount",                  {1,     1,    do_dummy}},
        {"powerctl",                {1,     1,    do_dummy}},
        {"restart",                 {1,     1,    do_dummy}},
        {"restorecon",              {1,     kMax, do_dummy}},
        {"restorecon_recursive",    {1,     kMax, do_dummy}},
        {"rm",                      {1,     1,    do_dummy}},
        {"rmdir",                   {1,     1,    do_dummy}},
        {"setprop",                 {2,     2,    do_dummy}},
        {"setrlimit",               {3,     3,    do_dummy}},
        {"start",                   {1,     1,    do_dummy}},
        {"stop",                    {1,     1,    do_dummy}},
        {"swapon_all",              {1,     1,    do_dummy}},
        {"symlink",                 {2,     2,    do_dummy}},
        {"sysclktz",                {1,     1,    do_dummy}},
        {"trigger",                 {1,     1,    do_dummy}},
        {"verity_load_state",       {0,     0,    do_dummy}},
        {"verity_update_state",     {0,     0,    do_dummy}},
        {"wait",                    {1,     2,    do_dummy}},
        {"wait_for_prop",           {2,     2,    do_dummy}},
        {"write",                   {2,     2,    do_dummy}},
    };
    // clang-format on
    return builtin_functions;
}

// override since UIDs on host don't make sense on device and we don't want to log errors for this

#undef getpwnam
passwd* getpwnam(const char*) {
    static passwd passwd = {
        .pw_uid = 0x1234,
    };
    return &passwd;
}
