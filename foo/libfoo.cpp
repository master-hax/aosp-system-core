#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" int __openat(int, const char*, int, int) {
    write(STDOUT_FILENO, "openat\n", strlen("openat\n"));
    abort();
}

extern "C" int __openat_2(int, const char*, int) {
    write(STDOUT_FILENO, "openat_2\n", strlen("openat_2\n"));
    abort();
}
