#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#define OPT_FORCE 1

static int usage()
{
    fprintf(stderr,"rm [-rR] [-f] <target>\n");
    return -1;
}

/* return -1 on failure, with errno set to the first error */
static int unlink_recursive(const char* name, int flags)
{
    struct stat st;
    DIR *dir;
    struct dirent *de;
    int fail = 0;

    /* is it a file or directory? */
    if (lstat(name, &st) < 0)
        return (flags & OPT_FORCE) ? 0 : -1;

    /* a file, so unlink it */
    if (!S_ISDIR(st.st_mode))
        return unlink(name);

    /* a directory, so open handle */
    dir = opendir(name);
    if (dir == NULL)
        return -1;

    /* recurse over components */
    errno = 0;
    while ((de = readdir(dir)) != NULL) {
        char dn[PATH_MAX];
        if (!strcmp(de->d_name, "..") || !strcmp(de->d_name, "."))
            continue;
        sprintf(dn, "%s/%s", name, de->d_name);
        if (unlink_recursive(dn, flags) < 0) {
            if (errno != ENOENT || !(flags & OPT_FORCE)) {
                fail = 1;
                break;
            }
        }
        errno = 0;
    }
    /* in case readdir or unlink_recursive failed */
    if (fail || errno < 0) {
        int save = errno;
        closedir(dir);
        errno = save;
        return -1;
    }

    /* close directory handle */
    if (closedir(dir) < 0)
        return -1;

    /* delete target directory */
    return rmdir(name);
}

int rm_main(int argc, char *argv[])
{
    int ret;
    int i = 1;
    int c;
    int flags = 0;
    int recursive = 0;

    if (argc < 2)
        return usage();

    /* check flags */
    do {
        c = getopt(argc, argv, "frR");
        if (c == EOF)
            break;
        switch (c) {
        case 'f':
            flags |= OPT_FORCE;
            break;
        case 'r':
        case 'R':
            recursive = 1;
            break;
        }
    } while (1);

    i = optind;
    /* loop over the file/directory args */
    for (; i < argc; i++) {
        int ret = recursive ? unlink_recursive(argv[i], flags) : unlink(argv[i]);
        if (ret < 0) {
            if (errno == ENOENT && (flags & OPT_FORCE)) {
                return 0;
            }
            fprintf(stderr, "rm failed for %s, %s\n", argv[i], strerror(errno));
            return -1;
        }
    }

    return 0;
}

