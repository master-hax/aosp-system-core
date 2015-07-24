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

#ifndef _INIT_ACTION_H
#define _INIT_ACTION_H

#include <map>
#include <queue>
#include <string>
#include <vector>

class Action {
public:
    Action() { }
    void add_command(int (*f)(int nargs, char** args), int nargs,
                     char** args, const std::string& filename = "", int line = 0);

    bool init_single_trigger(const std::string& name);
    bool init_triggers(int nargs, char** args, std::string* err);
    int num_commands() const;
    void execute_one_command(int command) const;
    void execute_all_commands() const;
    bool check_event_trigger(const std::string& trigger) const;
    bool check_property_trigger(const std::string& name = "", const std::string& value = "") const;
    bool triggers_equal(const class Action& other) const;
    std::string build_triggers_string() const;
    void dump_state() const;

private:
    class Command;

    void execute_command(Command& command) const;
    bool check_property_triggers(const std::string& name = "", const std::string& value = "") const;

    std::map<std::string, std::string> property_triggers;
    std::string event_trigger;
    std::vector<Command*> commands;

};

class ActionManager {
public:
    static ActionManager& get_instance() {
        static ActionManager instance;
        return instance;
    }

    void queue_event_trigger(const std::string& trigger);
    void queue_property_trigger(const std::string& name, const std::string& value);
    void queue_all_property_triggers();
    void queue_builtin_action(int (*func)(int nargs, char** args), const std::string& name);
    void execute_one_command();
    bool has_more_commands() const;
    Action* add_new_action(int nargs, char** args, std::string* err);
    void dump_state() const;

private:

    std::vector<Action*> action_list;
    std::queue<Action*> action_queue;
    int cur_command;

    ActionManager() : cur_command(0) { }
    ~ActionManager() { }

    ActionManager(ActionManager const&) = delete;
    void operator=(ActionManager const&) = delete;
};

#endif
