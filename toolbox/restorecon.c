#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/android.h>

static const char *progname;

static void usage(void)
{
    fprintf(stderr, "usage:  %s [-nrRv] pathname...\n", progname);
    exit(1);
}

int restorecon_main(int argc, char **argv)
{
    int ch, recurse = 0, i, rc;
    unsigned int options = 0;

    progname = argv[0];

    do {
        ch = getopt(argc, argv, "nrRv");
        if (ch == EOF)
            break;
        switch (ch) {
        case 'n':
            options |= SELINUX_ANDROID_RESTORECON_NOCHANGE;
            break;
        case 'r':
        case 'R':
            recurse = 1;
            break;
        case 'v':
            options |= SELINUX_ANDROID_RESTORECON_VERBOSE;
            break;
        default:
            usage();
        }
    } while (1);

    argc -= optind;
    argv += optind;
    if (!argc)
        usage();

    selinux_android_restorecon_set_options(options);

    for (i = 0; i < argc; i++) {
        if (recurse)
            rc = selinux_android_restorecon_recursive(argv[i]);
        else
            rc = selinux_android_restorecon(argv[i]);
        if (rc < 0)
            fprintf(stderr, "Could not restorecon %s:  %s\n", argv[i],
                    strerror(errno));
    }

    return 0;
}
