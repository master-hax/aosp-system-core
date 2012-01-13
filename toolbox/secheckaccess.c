#include <selinux/selinux.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

int secheckaccess_main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "usage:  %s scon tcon tclass permission\n",
			argv[0]);
		exit(1);
	}

	if (selinux_check_access(argv[1], argv[2], argv[3], argv[4], NULL)) {
	        printf("Error:  %s\n", strerror(errno));
		exit(1);
	}

	printf("Permission granted\n");
	exit(0);
}
