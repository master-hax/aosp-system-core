#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

extern int init_module(void *, unsigned long, const char *);

#define min(x,y) ((x) < (y) ? (x) : (y))
int insmod_main(int argc, char **argv)
{
	int fd;
	off_t len;
	void *file;
	ssize_t size = 0;
	char opts[1024];
	int ret = -1;

	/* make sure we've got an argument */
	if (argc < 2) {
		fprintf(stderr, "usage: insmod <module.o>\n");
		return -1;
	}

	/* read the file into memory */
	if (((fd = open(argv[1], O_RDONLY)) == -1) ||
	    ((len = lseek(fd, 0, SEEK_END)) == -1)) {
		fprintf(stderr, "insmod: can't open '%s'\n", argv[1]);
		goto bail;
	}
	size = (len + 4095) & ~4095;
	file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) goto bail;

	opts[0] = '\0';
	if (argc > 2) {
		int i, len;
		char *end = opts + sizeof(opts) - 1;
		char *ptr = opts;

		for (i = 2; (i < argc) && (ptr < end); i++) {
			len = min(strlen(argv[i]), (size_t)(end - ptr));
			memcpy(ptr, argv[i], len);
			ptr += len;
			*ptr++ = ' ';
		}
		*(ptr - 1) = '\0';
	}

	/* pass it to the kernel */
	ret = init_module(file, len, opts);
	if (ret != 0) {
		fprintf(stderr,
                "insmod: init_module '%s' failed (%s)\n",
                argv[1], strerror(errno));
	}

	/* unmap and close */
	munmap(file, size);
bail:
	if (fd) close(fd);
	return ret;
}

