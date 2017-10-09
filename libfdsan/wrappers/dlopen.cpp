#include <dlfcn.h>

#include "fdsan.h"

void* dlopen(const char* filename, int flags) {
  static auto __real_dlopen = reinterpret_cast<decltype(&dlopen)>(dlsym(RTLD_NEXT, "dlopen"));
  void* result = __real_dlopen(filename, flags);
  if (result) {
    fdsan_update_map();
  }
  return result;
}
