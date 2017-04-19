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

#include "action.h"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "util.h"

using android::base::Join;
using android::base::StringPrintf;

Command::Command(BuiltinFunction f, const std::vector<std::string>& args, int line)
    : func_(f), args_(args), line_(line) {}

int Command::InvokeFunc() const {
    std::vector<std::string> expanded_args;
    expanded_args.resize(args_.size());
    expanded_args[0] = args_[0];
    for (std::size_t i = 1; i < args_.size(); ++i) {
        if (!expand_props(args_[i], &expanded_args[i])) {
            LOG(ERROR) << args_[0] << ": cannot expand '" << args_[i] << "'";
            return -EINVAL;
        }
    }

    return func_(expanded_args);
}

std::string Command::BuildCommandString() const {
    return Join(args_, ' ');
}

bool PropertyTrigger::Parse(const std::string& trigger, std::string* err) {
    const static std::string prop_str("property:");
    std::string without_prefix(trigger.substr(prop_str.length()));

    auto parts = android::base::Split(without_prefix, "=");
    if (parts.size() != 2 || parts[0].empty() || parts[1].empty()) {
        *err = "ill-formed property trigger";
        return false;
    }

    name_ = parts[0];
    value_ = parts[1];

    if (name_.back() == '!') {
        negative_ = true;
        name_.pop_back();
        if (name_.empty()) {
            *err = "ill-formed property trigger";
            return false;
        }
    }

    return true;
}

// Table of potential overlaps
// Trigger     Other        Overlap?
// value =/!   value  =/!
// X     =     X      =     Y - Cannot have two positive triggers
// X     =     X      !     Y - Cannot match and not match the same value
// X     =     Y      =     Y - Cannot have two positive triggers
// X     =     Y      !     N

// X     !     X      =     Y - Cannot match and not match the same value
// X     !     X      !     Y - Cannot have two negative triggers for the same value
// X     !     Y      =     N
// X     !     Y      !     N

// Y     =     X      =     Y - Cannot have two positive triggers
// Y     =     X      !     N
// Y     =     Y      =     Y - Cannot have two positive triggers
// Y     =     Y      !     Y - Cannot match and not match the same value

// Y     !     X      =     N
// Y     !     X      !     N
// Y     !     Y      =     Y - Cannot match and not match the same value
// Y     !     Y      !     Y - Cannot have two negative triggers for the same value

bool PropertyTrigger::Overlaps(const PropertyTrigger& other, std::string* err) const {
    if (other.name_ != name_) return false;

    if (!negative_ && other.negative_ == negative_) {
        *err = "cannot have two positive triggers for the same property name";
        return true;
    }

    if (other.value_ == value_) {
        if (other.negative_ != negative_) {
            *err = "cannot match and not match the same value for the same property name";
            return true;
        }
        if (other.negative_ == negative_) {
            *err =
                "cannot have two negative triggers for the same value for the same property name";
            return true;
        }
    }

    return false;
}

bool PropertyTrigger::IsTrue(const std::string& name, const std::string& value) const {
    if (name_ == name) return IsTrue(value);

    return IsTrue(android::base::GetProperty(name_, ""));
}

bool PropertyTrigger::IsTrue(const std::string& value) const {
    if (negative_) {
        // on property:a!=* means that property a has not been set or is set to an empty value.
        if (value_ == "*") return value.empty();
        // on property a!=b: return that our value isn't the current value
        return value_ != value;
    } else {
        // on property:a=* means that a property has been set to any non-empty value
        if (value_ == "*") return !value.empty();
        // on property:a=b: return that our value is the current value
        return value_ == value;
    }
}

bool PropertyTrigger::IsTriggeredBy(const std::string& name) const {
    // Only changes to positive triggers cause an action to be triggered
    // If someone wants to trigger on all changes to a property that are not equal to a
    // certain value, they can use
    // on property:a=* && property:a!=b
    return name_ == name && !negative_;
}

std::string PropertyTrigger::ToString() const {
    return "property:" + name_ + (negative_ ? "!=" : "=") + value_;
}

Action::Action(bool oneshot, const std::string& filename, int line)
    : oneshot_(oneshot), filename_(filename), line_(line) {}

const KeywordMap<BuiltinFunction>* Action::function_map_ = nullptr;

bool Action::AddCommand(const std::vector<std::string>& args, int line, std::string* err) {
    if (!function_map_) {
        *err = "no function map available";
        return false;
    }

    if (args.empty()) {
        *err = "command needed, but not provided";
        return false;
    }

    auto function = function_map_->FindFunction(args[0], args.size() - 1, err);
    if (!function) {
        return false;
    }

    AddCommand(function, args, line);
    return true;
}

void Action::AddCommand(BuiltinFunction f, const std::vector<std::string>& args, int line) {
    commands_.emplace_back(f, args, line);
}

std::size_t Action::NumCommands() const {
    return commands_.size();
}

void Action::ExecuteOneCommand(std::size_t command) const {
    // We need a copy here since some Command execution may result in
    // changing commands_ vector by importing .rc files through parser
    Command cmd = commands_[command];
    ExecuteCommand(cmd);
}

void Action::ExecuteAllCommands() const {
    for (const auto& c : commands_) {
        ExecuteCommand(c);
    }
}

void Action::ExecuteCommand(const Command& command) const {
    Timer t;
    int result = command.InvokeFunc();

    double duration_ms = t.duration_s() * 1000;
    // Any action longer than 50ms will be warned to user as slow operation
    if (duration_ms > 50.0 ||
        android::base::GetMinimumLogSeverity() <= android::base::DEBUG) {
        std::string trigger_name = BuildTriggersString();
        std::string cmd_str = command.BuildCommandString();
        std::string source = StringPrintf(" (%s:%d)", filename_.c_str(), command.line());

        LOG(INFO) << "Command '" << cmd_str << "' action=" << trigger_name << source
                  << " returned " << result << " took " << duration_ms << "ms.";
    }
}

bool Action::InitTriggers(const std::vector<std::string>& args, std::string* err) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i].empty()) {
            *err = "empty trigger is not valid";
            return false;
        }

        if (i % 2) {
            if (args[i] != "&&") {
                *err = "&& is the only symbol allowed to concatenate actions";
                return false;
            } else {
                continue;
            }
        }

        if (android::base::StartsWith(args[i], "property:")) {
            PropertyTrigger property_trigger;
            if (!property_trigger.Parse(args[i], err)) {
                return false;
            }
            if (std::any_of(property_triggers_.begin(), property_triggers_.end(),
                            [&err, &property_trigger](const auto& other_trigger) {
                                return property_trigger.Overlaps(other_trigger, err);
                            })) {
                return false;
            }
            property_triggers_.emplace_back(property_trigger);
        } else {
            if (!event_trigger_.empty()) {
                *err = "multiple event triggers are not allowed";
                return false;
            }

            event_trigger_ = args[i];
        }
    }

    return true;
}

bool Action::InitSingleTrigger(const std::string& trigger) {
    std::vector<std::string> name_vector{trigger};
    std::string err;
    bool ret = InitTriggers(name_vector, &err);
    if (!ret) {
        LOG(ERROR) << "InitSingleTrigger failed due to: " << err;
    }
    return ret;
}

bool Action::CheckPropertyTriggers(const std::string& name, const std::string& value) const {
    return std::all_of(property_triggers_.begin(), property_triggers_.end(),
                       [&name, &value](const auto& property_trigger) {
                               return property_trigger.IsTrue(name, value);
                       });
}

bool Action::CheckEvent(const EventTrigger& event_trigger) const {
    return event_trigger == event_trigger_ && CheckPropertyTriggers();
}

bool Action::CheckEvent(const PropertyChange& property_change) const {
    // Cannot use structured bindings as lambda captures
    const auto& name = property_change.first;
    const auto& value = property_change.second;

    // If this action has an event trigger then it is not triggered by property changes
    if (!event_trigger_.empty()) return false;

    // If none of this action's property triggers correspond to 'name', then it will not be
    // triggered by this property change.
    if (std::none_of(
            property_triggers_.begin(), property_triggers_.end(),
            [&name](const auto& property_trigger) {
                return property_trigger.IsTriggeredBy(name);
            })) {
        return false;
    }

    return CheckPropertyTriggers(name, value);
}

bool Action::CheckEvent(const BuiltinAction& builtin_action) const {
    return this == builtin_action;
}

std::string Action::BuildTriggersString() const {
    std::vector<std::string> triggers;

    if (!event_trigger_.empty()) {
        triggers.emplace_back(event_trigger_);
    }
    for (const auto& property_trigger : property_triggers_) {
        triggers.emplace_back(property_trigger.ToString());
    }

    return Join(triggers, " && ");
}

void Action::DumpState() const {
    std::string trigger_name = BuildTriggersString();
    LOG(INFO) << "on " << trigger_name;

    for (const auto& c : commands_) {
        std::string cmd_str = c.BuildCommandString();
        LOG(INFO) << "  " << cmd_str;
    }
}

ActionManager::ActionManager() : current_command_(0) {
}

ActionManager& ActionManager::GetInstance() {
    static ActionManager instance;
    return instance;
}

void ActionManager::AddAction(std::unique_ptr<Action> action) {
    actions_.emplace_back(std::move(action));
}

void ActionManager::QueueEventTrigger(const std::string& trigger) {
    event_queue_.emplace(trigger);
}

void ActionManager::QueuePropertyChange(const std::string& name, const std::string& value) {
    event_queue_.emplace(std::make_pair(name, value));
}

void ActionManager::QueueAllPropertyActions() {
    // Property Actions have an empty event trigger and checking event triggers also checks,
    // that all associated property triggers are true, so this will match all true property
    // triggers.
    event_queue_.emplace("");
}

void ActionManager::QueueBuiltinAction(BuiltinFunction func, const std::string& name) {
    auto action = std::make_unique<Action>(true, "<Builtin Action>", 0);
    std::vector<std::string> name_vector{name};

    if (!action->InitSingleTrigger(name)) {
        return;
    }

    action->AddCommand(func, name_vector, 0);

    event_queue_.emplace(action.get());
    actions_.emplace_back(std::move(action));
}

void ActionManager::ExecuteOneCommand() {
    // Loop through the event queue until we have an action to execute
    while (current_executing_actions_.empty() && !event_queue_.empty()) {
        for (const auto& action : actions_) {
            if (std::visit([&action](const auto& event) { return action->CheckEvent(event); },
                           event_queue_.front())) {
                current_executing_actions_.emplace(action.get());
            }
        }
        event_queue_.pop();
    }

    if (current_executing_actions_.empty()) {
        return;
    }

    auto action = current_executing_actions_.front();

    if (current_command_ == 0) {
        std::string trigger_name = action->BuildTriggersString();
        LOG(INFO) << "processing action (" << trigger_name << ") from (" << action->filename()
                  << ":" << action->line() << ")";
    }

    action->ExecuteOneCommand(current_command_);

    // If this was the last command in the current action, then remove
    // the action from the executing list.
    // If this action was oneshot, then also remove it from actions_.
    ++current_command_;
    if (current_command_ == action->NumCommands()) {
        current_executing_actions_.pop();
        current_command_ = 0;
        if (action->oneshot()) {
            auto eraser = [&action] (std::unique_ptr<Action>& a) {
                return a.get() == action;
            };
            actions_.erase(std::remove_if(actions_.begin(), actions_.end(), eraser));
        }
    }
}

bool ActionManager::HasMoreCommands() const {
    return !current_executing_actions_.empty() || !event_queue_.empty();
}

void ActionManager::DumpState() const {
    for (const auto& a : actions_) {
        a->DumpState();
    }
}

bool ActionParser::ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                int line, std::string* err) {
    std::vector<std::string> triggers(args.begin() + 1, args.end());
    if (triggers.size() < 1) {
        *err = "actions must have a trigger";
        return false;
    }

    auto action = std::make_unique<Action>(false, filename, line);
    if (!action->InitTriggers(triggers, err)) {
        return false;
    }

    action_ = std::move(action);
    return true;
}

bool ActionParser::ParseLineSection(std::vector<std::string>&& args, int line, std::string* err) {
    return action_ ? action_->AddCommand(std::move(args), line, err) : false;
}

void ActionParser::EndSection() {
    if (action_ && action_->NumCommands() > 0) {
        action_manager_->AddAction(std::move(action_));
    }
}
