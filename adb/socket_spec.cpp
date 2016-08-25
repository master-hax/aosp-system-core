/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "socket_spec.h"

#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "sysdeps.h"

using android::base::StartsWith;
using android::base::StringPrintf;

struct LocalSocketType {
    int socket_namespace;
    bool available;
};

#if defined(__linux__)
#define ADB_LINUX 1
#else
#define ADB_LINUX 0
#endif

#if defined(_WIN32)
#define ADB_WINDOWS 1
#else
#define ADB_WINDOWS 0
#endif

static auto& kLocalSocketTypes = *new std::unordered_map<std::string, LocalSocketType>({
#if ADB_HOST
    { "local", { ANDROID_SOCKET_NAMESPACE_FILESYSTEM, !ADB_WINDOWS } },
#else
    { "local", { ANDROID_SOCKET_NAMESPACE_RESERVED, !ADB_WINDOWS } },
#endif

    { "localreserved", { ANDROID_SOCKET_NAMESPACE_RESERVED, !ADB_HOST } },
    { "localabstract", { ANDROID_SOCKET_NAMESPACE_ABSTRACT, ADB_LINUX } },
    { "localfilesystem", { ANDROID_SOCKET_NAMESPACE_FILESYSTEM, !ADB_WINDOWS } },
});

static bool parse_tcp_spec(const std::string& spec, std::string* hostname, int* port,
                           std::string* error) {
    std::vector<std::string> fragments = android::base::Split(spec, ":");
    if (fragments.size() == 1 || fragments.size() > 3) {
        *error = StringPrintf("invalid tcp specification: '%s'", spec.c_str());
        return false;
    }

    if (fragments[0] != "tcp") {
        *error = StringPrintf("specification is not tcp: '%s'", spec.c_str());
        return false;
    }

    // strtol accepts leading whitespace.
    const std::string& port_str = fragments.back();
    if (port_str.empty() || port_str[0] < '0' || port_str[0] > '9') {
        *error = StringPrintf("invalid port '%s'", port_str.c_str());
        return false;
    }

    char* parsed_end;
    long parsed_port = strtol(port_str.c_str(), &parsed_end, 10);
    if (*parsed_end != '\0') {
        *error = StringPrintf("trailing chars in port: '%s'", port_str.c_str());
        return false;
    }
    if (parsed_port > 65535) {
        *error = StringPrintf("invalid port %ld", parsed_port);
        return false;
    }

    // tcp:123 is valid, tcp::123 isn't.
    if (fragments.size() == 2) {
        // Empty hostname.
        if (hostname) {
            *hostname = "";
        }
    } else {
        if (fragments[1].empty()) {
            *error = StringPrintf("empty host in '%s'", spec.c_str());
            return false;
        }
        if (hostname) {
            *hostname = fragments[1];
        }
    }

    if (port) {
        *port = parsed_port;
    }

    return true;
}

bool socket_spec_handled(const std::string& spec) {
    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            return true;
        }
    }
    return StartsWith(spec, "tcp:");
}

bool socket_spec_validate(const std::string& spec, std::string* error) {
    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            if (!it.second.available) {
                *error = StringPrintf("%s is unavailable on this platform", it.first.c_str());
                return false;
            }

            return true;
        }
    }

    if (StartsWith(spec, "tcp:")) {
        return parse_tcp_spec(spec, nullptr, nullptr, error);
    }

    *error = StringPrintf("unknown socket specification '%s'", spec.c_str());
    return false;
}

int socket_spec_connect(const std::string& spec, std::string* error) {
    if (StartsWith(spec, "tcp:")) {
        std::string hostname;
        int port;
        if (!parse_tcp_spec(spec, &hostname, &port, error)) {
            return -1;
        }

        int result;
        if (hostname.empty() || hostname == "localhost") {
            result = network_loopback_client(port, SOCK_STREAM, error);
        } else {
#if ADB_HOST
            result = network_connect(hostname, port, SOCK_STREAM, 0, error);
#else
            // Disallow arbitrary connections in adbd.
            *error = "adbd does not support arbitrary tcp connections";
            return -1;
#endif
        }

        if (result >= 0) {
            disable_tcp_nagle(result);
        }
        return result;
    }

    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            if (!it.second.available) {
                *error = StringPrintf("attempted to connect to unavailable socket type: '%s'",
                                      spec.c_str());
                return -1;
            }

            return network_local_client(&spec[prefix.length()], it.second.socket_namespace,
                                        SOCK_STREAM, error);
        }
    }

    *error = StringPrintf("unknown socket specification '%s'", spec.c_str());
    return -1;
}

int socket_spec_listen(const std::string& spec, bool tcp_listen_all, std::string* error) {
    if (StartsWith(spec, "tcp:")) {
        std::string hostname;
        int port;
        if (!parse_tcp_spec(spec, &hostname, &port, error)) {
            return -1;
        }

        if (hostname.empty() && tcp_listen_all) {
            return network_inaddr_any_server(port, SOCK_STREAM, error);
        } else if (hostname.empty() || hostname == "localhost") {
            return network_loopback_server(port, SOCK_STREAM, error);
        } else {
            // TODO: Implement me.
            *error = "listening on specified hostname currently unsupported";
            return -1;
        }
    }

    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            if (!it.second.available) {
                *error = StringPrintf("attempted to listen on unavailable socket type: '%s'",
                                      spec.c_str());
                return -1;
            }

            return network_local_server(&spec[prefix.length()], it.second.socket_namespace,
                                        SOCK_STREAM, error);
        }
    }

    *error = StringPrintf("unknown socket specification '%s'", spec.c_str());
    return -1;
}
