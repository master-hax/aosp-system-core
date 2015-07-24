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

#include <list>
#include <map>
#include <string>

class Action {
public:
    friend class ActionQueue;
    Action() { }
    void add_command(int (*f)(int nargs, char** args), int nargs,
                     char** args, const std::string& filename = "", int line = 0);

    bool init_single_trigger(const std::string& name);
    void execute_all_commands() const;

private:
    class Command
    {
    public:
        friend class ActionQueue;
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

    bool init_triggers(int nargs, char** args, std::string* err);
    bool check_property_triggers(const std::string& name = "", const std::string& value = "") const;
    bool check_event_trigger(const std::string& trigger) const;
    bool check_property_trigger(const std::string& name = "", const std::string& value = "") const;
    bool triggers_equal(const class Action& other) const;
    std::string build_triggers_string() const;

    std::map<std::string, std::string> property_triggers;
    std::string event_trigger;
    std::list<Command*> commands;

};

class ActionQueue {
public:
    static ActionQueue& getInstance() {
        static ActionQueue instance;
        return instance;
    }

    void queue_event_trigger(const std::string& trigger);
    void queue_property_trigger(const std::string& name, const std::string& value);
    void queue_all_property_triggers();
    void queue_builtin_action(int (*func)(int nargs, char** args), const std::string& name);
    void execute_one_command();
    bool has_more_commands() const;
    Action* parse_action(int nargs, char** args, std::string* err);
    void dump_parser_state() const;

private:

    std::list<Action*> action_list;
    std::list<Action*> action_queue;
    Action* cur_action;
    std::list<Action::Command*>::iterator cur_command_it;

    ActionQueue() { }
    ~ActionQueue() { }

    ActionQueue(ActionQueue const&) = delete;
    void operator=(ActionQueue const&) = delete;
};

#endif
