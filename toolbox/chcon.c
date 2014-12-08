#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>

typedef int (*pfnsetfilecon)(const char *path, const char *con);

static void usage(const char *prog_name)
{
    fprintf(stderr, "usage:  %s [ -h Label symbolic links ] context path...\n",
                   prog_name);
}

int chcon_main(int argc, char **argv)
{
    int rc, i, c;

    pfnsetfilecon setfcon = setfilecon;

    while ((c=getopt(argc, argv, "h")) != -1) {
        switch (c) {
        case 'h':
            setfcon = lsetfilecon;
            break;
        case '?':
            if (isprint(optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf(stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
            }
            /* intentionally fall through to default */
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (argc - optind < 2) {
        usage(argv[0]);
        exit(1);
    }

    for (i = optind + 1; i < argc; i++) {
        rc = setfcon(argv[i], argv[optind]);
        if (rc < 0) {
            fprintf(stderr, "%s:  Could not label %s with %s:  %s\n",
                    argv[0], argv[i], argv[optind], strerror(errno));
            exit(2);
        }
    }
    exit(0);
}
