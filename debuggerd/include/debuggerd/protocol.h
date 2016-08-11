#pragma once

#include <stdint.h>

// Sockets in the ANDROID_SOCKET_NAMESPACE_RESERVED namespace.
// Both sockets are SOCK_SEQPACKET sockets, so no explicit length field is needed.
constexpr char kTombstonedCrashSocketName[] = "tombstoned_crash";
constexpr char kTombstonedInterceptSocketName[] = "tombstoned_intercept";

enum class CrashPacketType : uint8_t {
  // Initial request from crash_dump.
  kDumpRequest = 0,

  // Notification of a completed crash dump.
  // Sent after a dump is completed and the process has been untraced, but
  // before it has been resumed with SIGCONT.
  kCompletedDump,

  // Responses to kRequest.
  // kPerformDump sends along an output fd via cmsg(3).
  kPerformDump = 128,
  kAbortDump,
};

struct DumpRequest {
  int32_t pid;
};

// The full packet must always be written, regardless of whether the union is used.
struct TombstonedCrashPacket {
  CrashPacketType packet_type;
  union {
    DumpRequest dump_request;
  } packet;
};


// Comes with a file descriptor via SCM_RIGHTS.
// This packet should be sent before an actual dump happens.
struct InterceptRequest {
  int32_t pid;
};

// Sent either immediately upon failure, or when the intercept has been used.
struct InterceptResponse {
  uint8_t success; // 0 or 1
  char error_message[127]; // always null-terminated
};
