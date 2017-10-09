#include "fdsan.h"

#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <vector>

#include <async_safe/log.h>
#include <backtrace/Backtrace.h>

struct FdsanBacktrace {
  std::unique_ptr<Backtrace> backtrace;
};

void fdsan_free(FdsanBacktrace* backtrace) {
  delete backtrace;
}

FdsanBacktrace* fdsan_record_backtrace() {
  // TODO: Presumably, this is stale after a dlopen?
  static BacktraceMap* backtrace_map = BacktraceMap::CreateNew(getpid());

  if (!backtrace_map) {
    async_safe_fatal("failed to create map");
  }

  std::unique_ptr<Backtrace> backtrace(Backtrace::CreateNew(getpid(), gettid(), backtrace_map));
  if (!backtrace) {
    async_safe_fatal("failed to create backtrace");
  }

  if (!backtrace->Unwind(3)) {
    async_safe_fatal("failed to unwind");
  }

  return new FdsanBacktrace{
      .backtrace = std::move(backtrace),
  };
}

void fdsan_report_backtrace(const FdsanBacktrace* fdsan_backtrace) {
  if (!fdsan_backtrace) {
    return;
  }

  auto backtrace = fdsan_backtrace->backtrace.get();
  if (!backtrace) {
    async_safe_fatal("missing backtrace");
  }

  for (size_t i = 0; i < backtrace->NumFrames(); ++i) {
    // TODO: This starts with #03...
    std::string formatted = backtrace->FormatFrameData(i);
    async_safe_format_log(ANDROID_LOG_ERROR, "fdsan", "    %s", formatted.c_str());
  }
}
