#define LOG_TAG "oemlib"
#include <log/log.h>

static __attribute__((constructor)) void test_lib_init() {
  ALOGD("%s loaded", LIBNAME);
}
