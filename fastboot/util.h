#pragma once

#include <inttypes.h>
#include <stdlib.h>

#include <string>

#include <bootimg.h>


/* util stuff */
double now();
char* xstrdup(const char*);
void set_verbose();

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking. On Windows,
// if the mingw version of vsnprintf is used, use `gnu_printf' which allows z
// in %zd and PRIu64 (and related) to be recognized by the compile-time
// checking.
#define FASTBOOT_FORMAT_ARCHETYPE __printf__
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
#undef FASTBOOT_FORMAT_ARCHETYPE
#define FASTBOOT_FORMAT_ARCHETYPE gnu_printf
#endif
#endif
void die(const char* fmt, ...) __attribute__((__noreturn__))
__attribute__((__format__(FASTBOOT_FORMAT_ARCHETYPE, 1, 2)));
void verbose(const char* fmt, ...) __attribute__((__format__(FASTBOOT_FORMAT_ARCHETYPE, 1, 2)));
#undef FASTBOOT_FORMAT_ARCHETYPE
