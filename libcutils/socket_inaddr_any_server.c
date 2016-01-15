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

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#endif

#include <cutils/sockets.h>

#define LISTEN_BACKLOG 4

#if !defined(_WIN32)

/* open listen() port on any interface */
int socket_inaddr_any_server(int port, int type)
{
    struct sockaddr_in6 addr;
    int s, n;

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    s = socket(AF_INET6, type, 0);
    if (s < 0) return -1;

    n = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *) &n, sizeof(n));

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    if (type == SOCK_STREAM) {
        int ret;

        ret = listen(s, LISTEN_BACKLOG);

        if (ret < 0) {
            close(s);
            return -1; 
        }
    }

    return s;
}

#else

SOCKET socket_inaddr_any_server(int port, int type) {
    if (!initialize_sockets()) {
      return INVALID_SOCKET;
    }

    SOCKET sock = socket(AF_INET6, type, 0);
    if (sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    // Enforce exclusive addresses so nobody can steal the port from us (1),
    // and enable dual-stack so both IPv4 and IPv6 work (2).
    // (1) https://msdn.microsoft.com/en-us/library/windows/desktop/ms740621(v=vs.85).aspx.
    // (2) https://msdn.microsoft.com/en-us/library/windows/desktop/bb513665(v=vs.85).aspx.
    int exclusive = 1;
    DWORD v6_only = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&exclusive,
                   sizeof(exclusive)) == SOCKET_ERROR ||
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6_only,
                   sizeof(v6_only)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // Bind the socket to our local port.
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // Start listening for connections if this is a TCP socket.
    if (type == SOCK_STREAM && listen(sock, LISTEN_BACKLOG) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

#endif
