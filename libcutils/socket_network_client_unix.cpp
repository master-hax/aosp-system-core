/*
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <cutils/sockets.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

using namespace std::string_literals;

int socket_network_client_r(const char* host, int port, int type, std::string* error) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    addrinfo* addrs;
    const addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = type};
    int rc = getaddrinfo(host, port_str, &hints, &addrs);
    if (rc != 0) {
        *error = "failed to resolve host '"s + host + "': "s + gai_strerror(rc);
        return -1;
    }

    int result = -1;
    for (addrinfo* addr = addrs; addr != nullptr; addr = addr->ai_next) {
        // The Mac doesn't have SOCK_NONBLOCK.
        int s = socket(addr->ai_family, type, addr->ai_protocol);
        if (s == -1) break;

        if (connect(s, addr->ai_addr, addr->ai_addrlen) == 0) {
            result = s;
            break;
        }
        close(s);
    }

    if (result == -1) {
        *error = "failed to connect to '"s + host + ":"s + port_str + "': "s + strerror(errno);
    }

    freeaddrinfo(addrs);
    return result;
}

int socket_network_client(const char* host, int port, int type) {
    std::string error;
    return socket_network_client_r(host, port, type, &error);
}
