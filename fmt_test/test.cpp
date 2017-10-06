#include <stdio.h>

#include <async_safe/log.h>

void foo(char* fmt) {
  printf(fmt);
}

void bar(char* fmt) {
  async_safe_format_log(ANDROID_LOG_ERROR,
                        "actually the tag but mistakenly used as the format string %s %d",
                        fmt, 123123123);
}
