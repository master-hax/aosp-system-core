#include <stdlib.h>

#include "new"

#include "log_portability.h"

// Implement all new and delete operators as weak definitions

LIBLOG_WEAK void* operator new(std::size_t size) {
  if (size == 0) size = 1;
  void* p = ::malloc(size);
  return p;
}

LIBLOG_WEAK void operator delete(void* ptr) {
  if (ptr) ::free(ptr);
}
