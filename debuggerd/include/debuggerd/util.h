#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>
#include <android-base/unique_fd.h>

// Note: short reads aren't automatically handled by these functions.

// Sends a packet with an attached fd.
ssize_t send_fd(int sockfd, const void* _Nonnull data, size_t len, android::base::unique_fd fd);

// Receives a packet and optionally, its attached fd.
// If out_fd is non-null, packets can optionally have an attached fd.
// If out_fd is null, received packets must not have an attached fd.
//
// Errors:
//   EOVERFLOW: sockfd is SOCK_DGRAM or SOCK_SEQPACKET and buffer is too small.
//              The first len bytes of the packet are stored in data, but the
//              rest of the packet is dropped.
//   ERANGE:    too many file descriptors were attached to the packet.
//   ENOMSG:    not enough file descriptors were attached to the packet.
//
//   plus any errors returned by the underlying recvmsg.
ssize_t recv_fd(int sockfd, void* _Nonnull data, size_t len,
                android::base::unique_fd* _Nullable out_fd);
