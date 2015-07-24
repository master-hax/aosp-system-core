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

#include "action.h"
#include "error.h"
#include "init_parser.h"
#include "log.h"
#include "property_service.h"
#include "util.h"

class Action::Command
{
public:
    Command(int (*f)(int nargs, char** args),
            int nargs,
            char** args,
            const std::string& filename,
            int line) :
        func(f), nargs(nargs), filename(filename), line(line) {
        this->args = (char**)calloc(sizeof(char*), nargs);
        memcpy(this->args, args, sizeof(char*) * nargs);
    }

    ~Command() {
        free(args);
    }

    int invoke_func() const;

    std::string build_command_string() const;
    std::string build_source_string() const;

private:

    int (*func)(int nargs, char** args);
    int nargs;
    char** args;
    const std::string filename;
    int line;

};

int Action::Command::invoke_func() const
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

std::string Action::Command::build_command_string() const
{
    std::string ret;
    for (int i = 0; i < nargs; i++) {
        ret += args[i];
        ret += ' ';
    }
    ret.pop_back();
    return ret;
}

std::string Action::Command::build_source_string() const
{
    if (!filename.empty())
        return android::base::StringPrintf(" (%s:%d)", filename.c_str(), line);
    else
        return std::string();
}


void Action::add_command(int (*f)(int nargs, char** args), int nargs,
                         char** args, const std::string& filename, int line)
{
    Action::Command* cmd = new Action::Command(f, nargs, args, filename, line);
    commands.push_back(cmd);
}

bool Action::init_single_trigger(const std::string& name)
{
    const int nargs = 2;
    char* args[] = { 0, const_cast<char*>(name.c_str()), };
    std::string err_ret;

    return init_triggers(nargs, args, &err_ret);
}

int Action::num_commands() const
{
    return commands.size();
}

void Action::execute_one_command(int command) const
{
    execute_command(*commands[command]);
}

void Action::execute_all_commands() const
{
    for (auto& c : commands)
        execute_command(*c);
}

void Action::execute_command(Command& command) const
{
    Timer t;
    int result = command.invoke_func();

    if (klog_get_level() >= KLOG_INFO_LEVEL) {
        std::string trigger_name = build_triggers_string();
        std::string cmd_str = command.build_command_string();
        std::string source = command.build_source_string();

        INFO("Command '%s' action=%s%s returned %d took %.2fs\n",
             cmd_str.c_str(), trigger_name.c_str(), source.c_str(), result, t.duration());
    }
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

bool Action::check_property_triggers(const std::string& name,
                                     const std::string& value) const
{
    bool found = !name.compare("");
    if (property_triggers.empty())
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

bool Action::check_event_trigger(const std::string& trigger) const
{
    if (event_trigger.empty())
        return false;

    if (trigger.compare(event_trigger))
        return false;

    if (!check_property_triggers())
        return false;

    return true;
}

bool Action::check_property_trigger(const std::string& name,
                                    const std::string& value) const
{
    if (!event_trigger.empty())
        return false;

    return check_property_triggers(name, value);
}

bool Action::triggers_equal(const class Action& other) const
{
    return property_triggers.size() == other.property_triggers.size() &&
        std::equal(property_triggers.begin(), property_triggers.end(),
                   other.property_triggers.begin()) &&
        !event_trigger.compare(other.event_trigger);
}

std::string Action::build_triggers_string() const
{
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

void Action::dump_state() const
{
    INFO("on ");
    std::string trigger_name = build_triggers_string();
    INFO("%s", trigger_name.c_str());
    INFO("\n");

    for (auto& c : commands) {
        std::string cmd_str = c->build_command_string();
        INFO(" %s", cmd_str.c_str());
    }
    INFO("\n");
}

void ActionManager::queue_event_trigger(const std::string& trigger)
{
    for (auto& a : action_list) {
        if (a->check_event_trigger(trigger))
            action_queue.push(a);
    }
}

void ActionManager::queue_property_trigger(const std::string& name,
                                         const std::string& value)
{
    for (auto& a : action_list) {
        if (a->check_property_trigger(name, value))
            action_queue.push(a);
    }
}

void ActionManager::queue_all_property_triggers()
{
    queue_property_trigger("", "");
}

void ActionManager::queue_builtin_action(int (*func)(int nargs, char** args),
                                       const std::string& name)
{
    Action* act = new Action();
    if (!act->init_single_trigger(name))
        return;

    const int nargs = 1;
    char* args[] = { const_cast<char*>(name.c_str()), };
    act->add_command(func, nargs, args);

    action_queue.push(act);
}

void ActionManager::execute_one_command() {
    if (action_queue.empty()) {
        return;
    }

    Action* action = action_queue.front();
    if (!action->num_commands()) {
        action_queue.pop();
        return;
    }

    if (cur_command == 0) {
        std::string trigger_name = action->build_triggers_string();
        INFO("processing action %p (%s)\n", action, trigger_name.c_str());
    }

    action->execute_one_command(cur_command++);
    if (cur_command == action->num_commands()) {
        cur_command = 0;
        action_queue.pop();
    }
}

bool ActionManager::has_more_commands() const
{
    return !action_queue.empty();
}

Action* ActionManager::add_new_action(int nargs, char **args, std::string* err)
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

void ActionManager::dump_state() const
{
    for (auto& a : action_list) {
        a->dump_state();
    }
    INFO("\n");
}
