/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <errno.h>
#include <stdlib.h>

#include <base/stringprintf.h>
#include <vector>

#include "action.h"
#include "error.h"
#include "init_parser.h"
#include "log.h"
#include "property_service.h"
#include "util.h"

std::string Action::Command::build_command_string()
{
    std::string ret;
    for (int i = 0; i < nargs; i++) {
        ret += args[i];
        ret += ' ';
    }
    ret.pop_back();
    return ret;
}

std::string Action::Command::build_source_string()
{
    if (!filename.empty())
        return android::base::StringPrintf(" (%s:%d)", filename.c_str(), line);
    else
        return std::string();
}

int Action::Command::invoke_func()
{
    std::vector<std::string> strs;
    strs.resize(nargs);
    strs[0] = args[0];
    for (int i = 1; i < nargs; ++i) {
        if (expand_props(args[i], &strs[i]) == -1) {
            ERROR("%s: cannot expand '%s'\n", args[0], args[i]);
            return -EINVAL;
        }
    }

    std::vector<char*> args;
    for (auto& s : strs) {
        args.push_back(&s[0]);
    }

    return func(args.size(), &args[0]);
}

void Action::add_command(int (*f)(int nargs, char** args), int nargs,
                         char** args, const std::string& filename, int line)
{
    Action::Command* cmd = new Action::Command(f, nargs, args, filename, line);
    commands.push_back(cmd);
}

bool Action::init_triggers(int nargs, char** args, std::string* err)
{
    int i;

    for (i = 1; i < nargs; i++) {
        if (!(i % 2)) {
            if (strcmp(args[i], "&&")) {
                *err = "&& is the only symbol allowed to concatenate actions";
                return false;
            } else
                continue;
        }

        if (!strncmp(args[i], "property:", strlen("property:"))) {
            std::string prop_name(args[i] + strlen("property:"));
            size_t equal_pos = prop_name.find('=');
            if (equal_pos == std::string::npos) {
                *err = "property trigger found with matching '='";
                return false;
            }

            std::string prop_value(prop_name.substr(equal_pos + 1));
            prop_name.erase(equal_pos);

            auto res = property_triggers.emplace(prop_name, prop_value);
            if (res.second == false) {
                *err = "multiple property triggers found for same property";
                return false;
            }

        } else {
            if (!event_trigger.empty()) {
                *err = "multiple event triggers are not allowed";
                return false;
            }

            event_trigger = args[i];
        }
    }

    return true;
}

bool Action::init_single_trigger(const char* name)
{
    const int nargs = 2;
    char* args[] = { 0, const_cast<char*>(name), };
    std::string err_ret;

    return init_triggers(nargs, args, &err_ret);
}

bool Action::check_property_triggers(const std::string& name,
                                     const std::string& value)
{
    bool found = !name.compare("");
    if (property_triggers.size() == 0)
        return true;

    for (auto& t : property_triggers) {
        if (!t.first.compare(name)) {
            if (t.second.compare("*") &&
                t.second.compare(value))
                return false;
            else
                found = true;
        } else {
            std::string prop_val = property_get(t.first.c_str());
            if (prop_val.empty() ||
                (t.second.compare("*") &&
                 t.second.compare(prop_val)))
                return false;
        }
    }
    return found;
}

bool Action::check_event_trigger(const std::string& trigger)
{
    if (event_trigger.empty())
        return false;

    if (trigger.compare(event_trigger))
        return false;

    if (!check_property_triggers())
        return false;

    return true;
}

bool Action::check_property_trigger(const std::string& name, const std::string& value)
{
    if (!event_trigger.empty())
        return false;

    return check_property_triggers(name, value);
}

bool Action::triggers_equal(const class Action& other)
{
    return property_triggers.size() == other.property_triggers.size() &&
        std::equal(property_triggers.begin(), property_triggers.end(),
                   other.property_triggers.begin()) &&
        !event_trigger.compare(other.event_trigger);
}

std::string Action::build_triggers_string() {
    std::string result;

    for (auto& t : property_triggers) {
        result += t.first;
        result += '=';
        result += t.second;
        result += ' ';
    }
    if (!event_trigger.empty()) {
        result += event_trigger;
        result += ' ';
    }
    result.pop_back();
    return result;
}

void Action::execute_all_commands()
{
    for (auto& c : commands)
        c->invoke_func();
}

void ActionQueue::queue_event_trigger(const char *trigger)
{
    for (auto& a : action_list) {
        if (a->check_event_trigger(trigger))
            action_queue.push_back(a);
    }
}

void ActionQueue::queue_property_trigger(const char *name, const char *value)
{
    for (auto& a : action_list) {
        if (a->check_property_trigger(name, value))
            action_queue.push_back(a);
    }
}

void ActionQueue::queue_all_property_triggers()
{
    queue_property_trigger("", "");
}

void ActionQueue::queue_builtin_action(int (*func)(int nargs, char **args), const char *name)
{
    Action* act = new Action();
    if (!act->init_single_trigger(name))
        return;

    const int nargs = 1;
    char* args[] = { const_cast<char*>(name), };
    act->add_command(func, nargs, args);

    action_queue.push_back(act);
}

void ActionQueue::execute_one_command() {
    Timer t;

    if (!cur_action || cur_command_it == cur_action->commands.end()) {
        if (action_queue.empty()) {
            cur_action = nullptr;
            return;
        }
        cur_action = action_queue.front();
        action_queue.pop_front();

        cur_command_it = cur_action->commands.begin();
        if (cur_command_it == cur_action->commands.end())
            return;

        std::string trigger_name = cur_action->build_triggers_string();

        INFO("processing action %p (%s)\n", cur_action, trigger_name.c_str());
    }

    Action::Command* cur_command = *cur_command_it;
    int result = cur_command->invoke_func();

    if (klog_get_level() >= KLOG_INFO_LEVEL) {
        std::string trigger_name = cur_action->build_triggers_string();
        std::string cmd_str = cur_command->build_command_string();
        std::string source = cur_command->build_source_string();

        INFO("Command '%s' action=%s%s returned %d took %.2fs\n",
             cmd_str.c_str(), trigger_name.c_str(), source.c_str(), result, t.duration());
    }

    cur_command_it++;
}

bool ActionQueue::has_more_commands()
{
    return cur_command_it != cur_action->commands.end() || !action_queue.empty();
}

Action* ActionQueue::parse_action(int nargs, char **args, std::string* err)
{
    if (nargs < 2) {
        *err = "actions must have a trigger\n";
        return nullptr;
    }

    Action* act = new Action();
    if (!act->init_triggers(nargs, args, err)) {
        return nullptr;
    }

    auto old_act_it =
        std::find_if(action_list.begin(), action_list.end(),
                     [&] (Action* a) { return act->triggers_equal(*a); });

    if (old_act_it != action_list.end()) {
        delete act;
        return *old_act_it;
    }

    action_list.push_back(act);
    return act;
}

void ActionQueue::dump_parser_state()
{
    for (auto& a : action_list) {
        INFO("on ");
        std::string trigger_name = a->build_triggers_string();
        INFO("%s", trigger_name.c_str());
        INFO("\n");

        for (auto& c : a->commands) {
            INFO("  %p", c->func);
            std::string cmd_str = c->build_command_string();
            INFO(" %s", cmd_str.c_str());
        }
        INFO("\n");
    }
    INFO("\n");
}
