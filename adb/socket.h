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

#ifndef __ADB_SOCKET_H
#define __ADB_SOCKET_H

#include <stddef.h>

#include <deque>
#include <memory>
#include <string>

#include "fdevent.h"
#include "types.h"

class atransport;

/* An asocket represents one half of a connection between a local and
 * remote entity.  A local asocket is bound to a file descriptor.  A
 * remote asocket is bound to the protocol engine.
 */
struct asocket {
    virtual ~asocket() = default;

    /* enqueue is called by our peer when it has data
     * for us.  It should return 0 if we can accept more
     * data or 1 if not.  If we return 1, we must call
     * peer->ready() when we once again are ready to
     * receive data.
     */
    int (*enqueue)(asocket* s, apacket::payload_type data) = nullptr;

    /* ready is called by the peer when it is ready for
     * us to send data via enqueue again
     */
    void (*ready)(asocket* s) = nullptr;

    /* shutdown is called by the peer before it goes away.
     * the socket should not do any further calls on its peer.
     * Always followed by a call to close. Optional, i.e. can be NULL.
     */
    void (*shutdown)(asocket* s) = nullptr;

    /* close is called by the peer when it has gone away.
     * we are not allowed to make any further calls on the
     * peer once our close method is called.
     */
    void (*close)(asocket* s) = nullptr;

    size_t get_max_payload() const;

    /* A socket is bound to atransport */
    atransport* transport = nullptr;

    /* the unique identifier for this asocket
     */
    unsigned id = 0;

    /* flag: set when the socket's peer has closed
     * but packets are still queued for delivery
     */
    int closing = 0;

    // flag: set when the socket failed to write, so the socket will not wait to
    // write packets and close directly.
    bool has_write_error = false;

    // the asocket we are connected to
    asocket* peer = nullptr;
};

struct LocalSocket : public asocket {
    fdevent *fde = nullptr;
    int fd = -1;

    // Data waiting to be written to fd.
    IOVector packet_queue;

    // Only used in adbd (for root, unroot, etc.):
    // Quit adbd when both ends close the local service socket
    bool exit_on_close = false;
};

struct SmartSocket : public asocket {
    std::string smart_socket_data;
};

asocket* find_socket(unsigned local_id, unsigned remote_id);
void install_socket(asocket* s);
void remove_socket(asocket *s);
void close_all_sockets(atransport *t);

LocalSocket* create_local_socket(int fd);
asocket* create_local_service_socket(const char* destination, atransport* transport);

asocket *create_remote_socket(unsigned id, atransport *t);
void connect_to_remote(asocket *s, const char *destination);
void connect_to_smartsocket(asocket *s);

// Internal functions that are only made available here for testing purposes.
namespace internal {

#if ADB_HOST
char* skip_host_serial(char* service);
#endif

}  // namespace internal

#endif  // __ADB_SOCKET_H
