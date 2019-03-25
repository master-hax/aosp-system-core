/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "nativezygote_client.h"

#include <cutils/sockets.h>
#include <fcntl.h>

namespace android {
namespace init {

Result<pid_t> NativeZygoteClient::SendRequest(NativeZygoteRequest const& req) {
    if (!EnsureSocketOpen()) {
        return Error() << "Failed to connect to native zygote at \"" << socket_name_ << "\"";
    }

    std::string serialized_string;
    if (!req.SerializeToString(&serialized_string)) {
        return Error() << "Unable to serialize native zygote request";
    }

    if (serialized_string.size() > kMaxNativeZygoteRequestSize) {
        return Error() << "Serialized native zygote request exceed size limit";
    }

    // Send request.  If this fails, it's possible nativezygote has died and
    // restarted, leaving the previous socket dangling.  Reconnect and retry in
    // that case.
    const ssize_t serialized_size = serialized_string.size();
    if (write(socket_.get(), serialized_string.c_str(), serialized_size) != serialized_size) {
        CloseSocket();
        EnsureSocketOpen();
        if (write(socket_.get(), serialized_string.c_str(), serialized_size) != serialized_size) {
            return ErrnoError() << "Failed to send serialized native zygote request";
        }
    }

    pid_t pid;
    if (read(socket_.get(), &pid, sizeof(pid)) != sizeof(pid)) {
        CloseSocket();
        return ErrnoError() << "Failed to receive PID from native zygote";
    }
    return pid;
}

bool NativeZygoteClient::EnsureSocketOpen() {
    if (socket_ == -1) {
        int sock = socket_local_client(socket_name_.c_str(), ANDROID_SOCKET_NAMESPACE_RESERVED,
                                       SOCK_SEQPACKET);
        if (sock != -1) {
            // Native zygote is only used by init, not its children.
            fcntl(sock, F_SETFD, FD_CLOEXEC);
            socket_.reset(sock);
        }
    }
    return socket_ != -1;
}

void NativeZygoteClient::CloseSocket() {
    socket_.reset();
}

}  // namespace init
}  // namespace android
