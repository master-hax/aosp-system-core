/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include <android-base/file.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "services.h"
#include "sysdeps.h"
#include "transport.h"

int service_to_fd(const char* name, const atransport* transport) {
    return service_to_fd_shared(name, transport);
}

struct state_info {
    TransportType transport_type;
    std::string serial;
    ConnectionState state;
};

static void wait_for_state(int fd, void* data) {
    std::unique_ptr<state_info> sinfo(reinterpret_cast<state_info*>(data));

    D("wait_for_state %d", sinfo->state);

    while (true) {
        bool is_ambiguous = false;
        std::string error = "unknown error";
        const char* serial = sinfo->serial.length() ? sinfo->serial.c_str() : NULL;
        atransport* t = acquire_one_transport(sinfo->transport_type, serial, &is_ambiguous, &error);
        if (t != nullptr && (sinfo->state == kCsAny || sinfo->state == t->connection_state)) {
            SendOkay(fd);
            break;
        } else if (!is_ambiguous) {
            adb_pollfd pfd = {.fd = fd, .events = POLLIN };
            int rc = adb_poll(&pfd, 1, 1000);
            if (rc < 0) {
                SendFail(fd, error);
                break;
            } else if (rc > 0 && (pfd.revents & POLLHUP) != 0) {
                // The other end of the socket is closed, probably because the other side was
                // terminated, bail out.
                break;
            }

            // Try again...
        } else {
            SendFail(fd, error);
            break;
        }
    }

    adb_close(fd);
    D("wait_for_state is done");
}

static void connect_device(const std::string& address, std::string* response) {
    if (address.empty()) {
        *response = "empty address";
        return;
    }

    std::string serial;
    std::string host;
    int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    if (!android::base::ParseNetAddress(address, &host, &port, &serial, response)) {
        return;
    }

    std::string error;
    int fd = network_connect(host.c_str(), port, SOCK_STREAM, 10, &error);
    if (fd == -1) {
        *response = android::base::StringPrintf("unable to connect to %s: %s",
                                                serial.c_str(), error.c_str());
        return;
    }

    D("client: connected %s remote on fd %d", serial.c_str(), fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);

    // Send a TCP keepalive ping to the device every second so we can detect disconnects.
    if (!set_tcp_keepalive(fd, 1)) {
        D("warning: failed to configure TCP keepalives (%s)", strerror(errno));
    }

    int ret = register_socket_transport(fd, serial.c_str(), port, 0);
    if (ret < 0) {
        adb_close(fd);
        *response = android::base::StringPrintf("already connected to %s", serial.c_str());
    } else {
        *response = android::base::StringPrintf("connected to %s", serial.c_str());
    }
}

void connect_emulator(const std::string& port_spec, std::string* response) {
    std::vector<std::string> pieces = android::base::Split(port_spec, ",");
    if (pieces.size() != 2) {
        *response = android::base::StringPrintf("unable to parse '%s' as <console port>,<adb port>",
                                                port_spec.c_str());
        return;
    }

    int console_port = strtol(pieces[0].c_str(), NULL, 0);
    int adb_port = strtol(pieces[1].c_str(), NULL, 0);
    if (console_port <= 0 || adb_port <= 0) {
        *response = android::base::StringPrintf("Invalid port numbers: %s", port_spec.c_str());
        return;
    }

    // Check if the emulator is already known.
    // Note: There's a small but harmless race condition here: An emulator not
    // present just yet could be registered by another invocation right
    // after doing this check here. However, local_connect protects
    // against double-registration too. From here, a better error message
    // can be produced. In the case of the race condition, the very specific
    // error message won't be shown, but the data doesn't get corrupted.
    atransport* known_emulator = find_emulator_transport_by_adb_port(adb_port);
    if (known_emulator != nullptr) {
        *response = android::base::StringPrintf("Emulator already registered on port %d", adb_port);
        return;
    }

    // Check if more emulators can be registered. Similar unproblematic
    // race condition as above.
    int candidate_slot = get_available_local_transport_index();
    if (candidate_slot < 0) {
        *response = "Cannot accept more emulators";
        return;
    }

    // Preconditions met, try to connect to the emulator.
    std::string error;
    if (!local_connect_arbitrary_ports(console_port, adb_port, &error)) {
        *response = android::base::StringPrintf("Connected to emulator on ports %d,%d",
                                                console_port, adb_port);
    } else {
        *response = android::base::StringPrintf("Could not connect to emulator on ports %d,%d: %s",
                                                console_port, adb_port, error.c_str());
    }
}

static void connect_service(int fd, void* data) {
    char* host = reinterpret_cast<char*>(data);
    std::string response;
    if (!strncmp(host, "emu:", 4)) {
        connect_emulator(host + 4, &response);
    } else {
        connect_device(host, &response);
    }
    free(host);

    // Send response for emulator and device
    SendProtocolString(fd, response);
    adb_close(fd);
}

asocket* host_service_to_socket(const char* name, const char* serial) {
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker();
    } else if (android::base::StartsWith(name, "wait-for-")) {
        name += strlen("wait-for-");

        std::unique_ptr<state_info> sinfo(new state_info);
        if (sinfo == nullptr) {
            fprintf(stderr, "couldn't allocate state_info: %s", strerror(errno));
            return nullptr;
        }

        if (serial) sinfo->serial = serial;

        if (android::base::StartsWith(name, "local")) {
            name += strlen("local");
            sinfo->transport_type = kTransportLocal;
        } else if (android::base::StartsWith(name, "usb")) {
            name += strlen("usb");
            sinfo->transport_type = kTransportUsb;
        } else if (android::base::StartsWith(name, "any")) {
            name += strlen("any");
            sinfo->transport_type = kTransportAny;
        } else {
            return nullptr;
        }

        if (!strcmp(name, "-device")) {
            sinfo->state = kCsDevice;
        } else if (!strcmp(name, "-recovery")) {
            sinfo->state = kCsRecovery;
        } else if (!strcmp(name, "-sideload")) {
            sinfo->state = kCsSideload;
        } else if (!strcmp(name, "-bootloader")) {
            sinfo->state = kCsBootloader;
        } else if (!strcmp(name, "-any")) {
            sinfo->state = kCsAny;
        } else {
            return nullptr;
        }

        int fd = create_service_thread(wait_for_state, sinfo.release());
        return create_local_socket(fd);
    } else if (!strncmp(name, "connect:", 8)) {
        char* host = strdup(name + 8);
        int fd = create_service_thread(connect_service, host);
        return create_local_socket(fd);
    }
    return NULL;
}
