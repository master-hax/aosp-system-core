#pragma once

#include <stdbool.h>
#include <sys/cdefs.h>
#include <unistd.h>

__BEGIN_DECLS

enum DebuggerdDumpType {
  kDebuggerdBacktrace,
  kDebuggerdTombstone,
};

bool debuggerd_trigger_dump(pid_t pid, int output_fd, enum DebuggerdDumpType dump_type);

__END_DECLS
