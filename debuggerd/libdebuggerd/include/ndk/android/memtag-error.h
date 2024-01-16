#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

typedef enum : int16_t {
  AMEMTAG_CAUSE_TYPE_UNKNOWN,
  AMEMTAG_CAUSE_TYPE_OUT_OF_BOUNDS,
  AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
} AMemtagCauseType;

struct AMemtagCrashInfo;
struct AMemtagError;
struct AMemtagCause;
struct AMemtagStackTrace;

AMemtagCrashInfo* AMemtagCrashInfo_get(uintptr_t fault_address);
size_t AMemtagCrashInfo_getSize(AMemtagCrashInfo*);

AMemtagError* AMemtagError_get(AMemtagCrashInfo*);

size_t AMemtagError_getHumanReadable(AMemtagError*, char*, size_t);

AMemtagCause* AMemtagError_getCause(AMemtagError*, size_t);

AMemtagCauseType AMemtagCause_getType(AMemtagCause*);

uintptr_t AMemtagCause_getAllocationAddress(AMemtagCause*);

AMemtagStackTrace* AMemtagCause_getAllocationStack(AMemtagCause*);
pid_t AMemtagCause_getAllocationTid(AMemtagCause*);

// ONLY FOR AMEMTAG_CAUSE_TYPE_USE_AFTER_FREE
AMemtagStackTrace* AMemtagCause_getFreeStack(AMemtagCause*);
pid_t AMemtagCause_getFreeTid(AMemtagCause*);

uintptr_t AMemtagStackTrace_getPC(AMemtagStackTrace*, int n);
