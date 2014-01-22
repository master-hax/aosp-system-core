#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/xattr.h>
#include <sys/system_properties.h>

static int getrestoreconlast(char *pathname)
{
    char restorecon_last[PROP_VALUE_MAX];
    ssize_t size;

    size = getxattr(pathname, "security.restorecon_last", restorecon_last, sizeof restorecon_last);
    if (size < 0) {
        fprintf(stderr, "getxattr '%s' failed:  %s\n", pathname, strerror(errno));
        return -1;
    }
    restorecon_last[size] = 0;
    printf("%s %s (%d)\n", pathname, restorecon_last, size);
    return 0;
}

int getrestoreconlast_main(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++)
        getrestoreconlast(argv[i]);
    return 0;
}

