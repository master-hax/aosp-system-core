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

enum SubcontextMessage {
    kResult = 0,
    kExecuteCommand = 1,
};

enum ResultType {
    kSuccess = 0,
    kFailure = 1,
};

void SerializeResult(Serializer& serializer, const Result<Success>& result) {
    if (result.has_value()) {
        serializer.WriteUint32(kSuccess);
    } else {
        serializer.WriteUint32(kFailure);
        serializer.WriteString(result.error_string());
        serializer.WriteUint32(result.error_errno());
    }
}

Result<Result<Success>> DeserializeResult(Deserializer& deserializer) {
    auto result_type = deserializer.ReadUint32();
    if (!result_type) {
        return Error() << "Could not read result type";
    }

    switch (*result_type) {
        case kSuccess:
            return Result<Success>();
        case kFailure: {
            auto error_string = deserializer.ReadString();
            if (!error_string) return Error() << "Could not read error_string";
            auto result_errno = deserializer.ReadUint32();
            if (!error_string) return Error() << "Could not read error_errno";

            return Result<Success>(ResultError(*error_string, *result_errno));
        }
        default:
            return Error() << "Unknown result_type: " << *result_type;
    }
}

Result<Success> RunCommand(Deserializer& deserializer) {
    auto args = deserializer.ReadStrings();
    if (!args) {
        return Error() << "Could not deserialize arg for command: " << args.error();
    }

    auto map_result = subcontext_function_map->FindFunction(*args);
    if (!map_result) {
        return Error() << "Cannot find command: " << map_result.error();
    }

    return RunBuiltinFunction(map_result->second, *args);
}

Result<std::string> ReadMessage(int socket) {
    char buffer[4096] = {0};
    int result = TEMP_FAILURE_RETRY(recv(socket, buffer, sizeof(buffer), 0));
    if (result <= 0) {
        return ErrnoError();
    }
    return std::string(buffer, result);
}

Result<Success> SendMessage(int socket, const std::string& message) {
    if (auto result = TEMP_FAILURE_RETRY(send(socket, message.c_str(), message.size(), 0));
        result != static_cast<long>(message.size())) {
        return ErrnoError();
    }
    return Success();
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

        auto deserializer = Deserializer(*init_message);
        auto message_type = deserializer.ReadUint32();
        if (!message_type) {
            LOG(ERROR) << "Unable to receive message type from init: " << message_type.error();
            continue;
        }

        auto response = Serializer();
        switch (*message_type) {
            case kExecuteCommand: {
                auto result = RunCommand(deserializer);
                response.WriteUint32(kResult);
                SerializeResult(response, result);
                break;
            }
            default:
                LOG(ERROR) << "Unknown message type from init: " << *message_type;
                continue;
        }

        if (auto result = SendMessage(socket, response.contents()); !result) {
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
    auto serializer = Serializer();
    serializer.WriteUint32(kExecuteCommand);
    serializer.WriteStrings(args);

    if (serializer.contents().size() > 4096) {
        return Error() << "Command too long to send to subcontext";
    }

    if (auto result = SendMessage(socket_, serializer.contents()); !result) {
        return ErrnoError() << "Failed to send message to subcontext";
    }

    auto subcontext_message = ReadMessage(socket_);
    if (!subcontext_message) {
        return Error() << "Failed to receive result from subcontext: " << subcontext_message.error();
    }

    auto deserializer = Deserializer(*subcontext_message);
    auto message_type = deserializer.ReadUint32();
    if (!message_type) {
        return Error() << "Unable to receive message type from subcontext: " << message_type.error();
    }

    if (*message_type != kResult) {
        return Error() << "Unknown message type from subcontext: " << *message_type;
    }

    if (auto result = DeserializeResult(deserializer); !result) {
        return Error() << "Could not deserialize result from subcontext";
    } else {
        return *result;
    }
}

Subcontext::~Subcontext() {
    kill(pid_, SIGTERM);
    kill(pid_, SIGKILL);
}

}  // namespace init
}  // namespace android
