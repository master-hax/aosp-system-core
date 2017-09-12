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

#include "subcontext.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <selinux/android.h>

#include "action.h"
#include "system/core/init/subcontext.pb.h"
#include "util.h"

using android::base::Join;
using android::base::Socketpair;
using android::base::Split;
using android::base::StartsWith;
using android::base::unique_fd;

namespace android {
namespace init {

const KeywordFunctionMap* subcontext_function_map = nullptr;

namespace {

Result<std::string> ReadMessage(int socket) {
    char buffer[4096] = {0};
    int result = TEMP_FAILURE_RETRY(recv(socket, buffer, sizeof(buffer), 0));
    if (result <= 0) {
        return ErrnoError();
    }
    return std::string(buffer, result);
}

template <typename T>
Result<Success> SendMessage(int socket, const T& message) {
    std::string message_string;
    if (!message.SerializeToString(&message_string)) {
        return Error() << "Unable to serialize message";
    }

    if (message_string.size() > 4096) {
        return Error() << "Serialized message too long to send";
    }

    if (auto result =
            TEMP_FAILURE_RETRY(send(socket, message_string.c_str(), message_string.size(), 0));
        result != static_cast<long>(message_string.size())) {
        return ErrnoError();
    }
    return Success();
}

void SerializeResult(const Result<Success>& result, SubcontextReply::ResultMessage* result_message) {
    if (result) {
        result_message->set_success(true);
    } else {
        result_message->set_success(false);
        result_message->set_error_string(result.error_string());
        result_message->set_error_errno(result.error_errno());
    }
}

Result<Success> RunCommand(const SubcontextCommand::ExecuteCommand& execute_command) {
    // Need to use ArraySplice instead of this code.
    auto args = std::vector<std::string>();
    for (const auto& string : execute_command.args()) {
        args.emplace_back(string);
    }

    auto map_result = subcontext_function_map->FindFunction(args);
    if (!map_result) {
        return Error() << "Cannot find command: " << map_result.error();
    }

    return RunBuiltinFunction(map_result->second, args);
}

void SubcontextMain(unique_fd socket) {
    pollfd ufd[1];
    ufd[0].events = POLLIN;
    ufd[0].fd = socket;

    while (true) {
        ufd[0].revents = 0;
        int nr = poll(ufd, arraysize(ufd), -1);
        if (nr == 0) return;
        if (nr < 0) {
            PLOG(ERROR) << "poll() of subcontext socket failed, continuing";
            continue;
        }

        auto init_message = ReadMessage(socket);
        if (!init_message) {
            LOG(ERROR) << "Could not read message from init: " << init_message.error();
            continue;
        }

        auto subcontext_command = SubcontextCommand();
        if (!subcontext_command.ParseFromString(*init_message)) {
            LOG(ERROR) << "Unable to parse message from init";
            continue;
        }

        auto reply = SubcontextReply();
        switch (subcontext_command.command_case()) {
            case SubcontextCommand::kExecuteCommand: {
                auto result = RunCommand(subcontext_command.execute_command());
                auto result_message = reply.mutable_result();
                SerializeResult(result, result_message);
                break;
            }
            default:
                LOG(ERROR) << "Unknown message type from init: "
                           << subcontext_command.command_case();
                continue;
        }

        if (auto result = SendMessage(socket, reply); !result) {
            LOG(ERROR) << "Failed to send message to init: " << result.error();
            continue;
        }
    }
}

}  // namespace

void Subcontext::Fork() {
    unique_fd subcontext_socket;
    if (!Socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, &socket_, &subcontext_socket)) {
        LOG(FATAL) << "Could not create socket pair to communicate to subcontext";
        return;
    }

    auto result = fork();

    if (result == -1) {
        LOG(FATAL) << "Could not fork subcontext";
    } else if (result == 0) {
        socket_.reset();
        /*
        if (selinux_android_setcon(context_.c_str()) == -1) {
            PLOG(FATAL) << "Could not change context to '" << context_ << "'";
        }
        */
        //__system_properties_init();

        SubcontextMain(std::move(subcontext_socket));
        _exit(0);
    } else {
        subcontext_socket.reset();
        pid_ = result;
    }
}

Result<Success> Subcontext::Execute(const std::vector<std::string>& args) {
    auto subcontext_command = SubcontextCommand();
    auto execute_command = subcontext_command.mutable_execute_command();
    for (const auto& arg : args) {
        auto out_arg = execute_command->add_args();
        *out_arg = arg;
    }

    if (auto result = SendMessage(socket_, subcontext_command); !result) {
        return ErrnoError() << "Failed to send message to subcontext";
    }

    auto subcontext_message = ReadMessage(socket_);
    if (!subcontext_message) {
        return Error() << "Failed to receive result from subcontext: " << subcontext_message.error();
    }

    auto subcontext_reply = SubcontextReply();
    if (!subcontext_reply.ParseFromString(*subcontext_message)) {
        return Error() << "Unable to parse message from subcontext";
    }

    switch (subcontext_reply.reply_case()) {
        case SubcontextReply::kResult: {
            auto result = subcontext_reply.result();
            if (result.success()) {
                return Success();
            } else {
                return ResultError(result.error_string(), result.error_errno());
            }
        }
        default:
            return Error() << "Unknown message type from subcontext: "
                           << subcontext_reply.reply_case();
    }
}

Subcontext::~Subcontext() {
    kill(pid_, SIGTERM);
    kill(pid_, SIGKILL);
}

}  // namespace init
}  // namespace android
