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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>

#define LISTEN_BACKLOG 4

/* open listen() port on any interface */
int socket_inaddr_any_server(int port, int type, int* assigned_port) {
    struct sockaddr_in6 addr;
    int s, n;

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    s = socket(AF_INET6, type, 0);
    if (s < 0) {
        return -1;
    }

    n = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *) &n, sizeof(n));

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }
    socklen_t len = sizeof(addr);
    int ret = getsockname(s, reinterpret_cast<struct sockaddr*>(&addr), &len);
    if (ret < 0) {
        close(s);
        return ret;
    }
    *assigned_port = ntohs(addr.sin6_port);

    if (type == SOCK_STREAM) {
        ret = listen(s, LISTEN_BACKLOG);

        if (ret < 0) {
            close(s);
            return -1; 
        }
    }

    return s;
}
