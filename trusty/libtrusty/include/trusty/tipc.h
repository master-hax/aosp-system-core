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

#ifndef _LIB_TIPC_H
#define _LIB_TIPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/uio.h>
#include <trusty/ipc.h>

/**
 * DOC: Trusty IPC user-space Library
 *
 * **libtrusty** is a linux user-space library allowing a user-space program
 * to communicate with a secure service running on Trusty TEE via Trusty IPC.
 *
 * The user-space program starts a communication session by calling
 * tipc_connect(), initializing a connection to a specified Trusty
 * service. Internally, tipc_connect() call opens a specified device node
 * to obtain a file descriptor and invokes a %TIPC_IOC_CONNECT ioctl()
 * call with the `argp` parameter pointing to a string containing a service
 * name to which to connect.
 *
 * ..
 *     #define TIPC_IOC_MAGIC 'r'
 *     #define TIPC_IOC_CONNECT _IOW(TIPC_IOC_MAGIC, 0x80, char *)
 *
 * The resulting file descriptor can only be used to communicate with the
 * service for which it was created. The file descriptor should be closed by
 * calling tipc_close() when the connection is not required anymore.
 *
 * The file descriptor obtained by the tipc_connect() call behaves as a
 * typical character device node; the file descriptor:
 *
 *  * Can be switched to non-blocking mode if needed
 *  * Can be written to using a standard write() call to send messages to the
 *    other side
 *  * Can be polled (using poll() calls or select() calls)
 *    for availability of incoming messages as a regular file descriptor
 *  * Can be read to retrieve incoming messages
 *
 * A caller sends a message to the Trusty service by executing a write call for
 * the specified `fd`. All data passed to the above write() call is
 * transformed into a message by the trusty-ipc driver. The message is delivered
 * to the secure side where the data is handled by the IPC subsystem in the
 * Trusty kernel and routed to the proper destination and delivered to an app
 * event loop as an %IPC_HANDLE_POLL_MSG event on a particular channel handle.
 * Depending on the particular, service-specific protocol, the Trusty service
 * may send one or more reply messages that are delivered back to the non-secure
 * side and placed in the appropriate channel file descriptor message queue to
 * be retrieved by the user space application read() call.
 *
 * .. mermaid:: /content/concepts/ipc/dgm/messaging_ns.mmd
 *
 * *********
 * Reference
 * *********
 *
 * :ref:`tipc.h` exposes **libtrusty** API and is maintained in aosp at
 * :aosp_system_core:`trusty/libtrusty/include/trusty`
 *
 * A modified copy is placed here in order for the trusty doc to build, without
 * having references to Android repo. This dependency can be removed once the
 * Trusty SDK becomes available.
 */

/**
 * tipc_connect() - Opens a specified `tipc` device node and initiates
 * a connection to a specified Trusty service.
 * @dev_name: Path to the Trusty IPC device node to open
 * @srv_name: Name of a published Trusty service to which to connect
 *
 * Return: Valid file descriptor on success, -1 otherwise.
 */
int tipc_connect(const char* dev_name, const char* srv_name);

/**
 * tipc_send() - Supports sending memfds in addition to data from an iovec
 * @fd: file descriptor returned by tipc_connect()
 * @iov: pointer to the array of input &struct iovec
 * @iovcnt: number of entries in the `iov` array
 * @shm: pointer to the array of input &struct shmem
 * @shmcnt: number of entries in the `shm` array
 *
 * Return: number of bytes transmitted.
 */
ssize_t tipc_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shm, int shmcnt);

/**
 * tipc_close() - Closes the connection to the Trusty service
 * specified by a file descriptor.
 * @fd: File descriptor previously opened by a tipc_connect() call
 *
 * Return: %NO_ERROR on success, -1 otherwise.
 */
int tipc_close(int fd);

#ifdef __cplusplus
}
#endif

#endif  //_LIB_TIPC_H
