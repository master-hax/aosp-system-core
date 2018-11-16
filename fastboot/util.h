#pragma once

#include <inttypes.h>
#include <stdlib.h>

#include <string>

#include <bootimg.h>

/* util stuff */
double now();
void set_verbose();

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking.
void die(const char* fmt, ...) __attribute__((__noreturn__))
__attribute__((__format__(__printf__, 1, 2)));
void verbose(const char* fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

// Return whether or not a partition looks like it should be dynamic.
bool IsPartitionInSuperImage(const std::string& super_image, const std::string& partition_name);
