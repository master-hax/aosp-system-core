#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLK_SIZE 4096

int main(int argc, char* argv[]) {
    int rc = 1;

    int file_fd = -1;
    struct stat file_stbuf;
    size_t size_file;

    int blkdev_fd = -1;
    struct stat blkdev_stbuf;
    size_t size_blkdev;

    char* backup = NULL;
    size_t offset = 0;

    if (argc < 3) {
        printf("Usage: %s <filename> <blk dev>\n", argv[0]);
        return -1;
    }

    file_fd = open(argv[1], O_RDONLY);
    if (file_fd < 0) {
        printf("Couldn't open %s - %s\n", argv[1], strerror(errno));
        goto end;
    }

    blkdev_fd = open(argv[2], O_RDWR);
    if (blkdev_fd < 0) {
        printf("Couldn't open %s - %s\n", argv[2], strerror(errno));
        goto end;
    }

    if (fstat(file_fd, &file_stbuf) < 0) {
        printf("Couldn't stat() %s - %s\n", argv[1], strerror(errno));
        goto end;
    }

    if (fstat(blkdev_fd, &blkdev_stbuf) < 0) {
        printf("Couldn't stat() %s - %s\n", argv[2], strerror(errno));
        goto end;
    }

    /* Make sure source file is a regular file */
    if ((file_stbuf.st_mode & S_IFMT) != S_IFREG) {
        printf("%s is not a regular file\n", argv[1]);
        goto end;
    }

    /* And make sure destination is a block device */
    if ((blkdev_stbuf.st_mode & S_IFMT) != S_IFBLK) {
        printf("%s is not a block device\n", argv[2]);
        goto end;
    }

    /* Get size of block device */
    if (ioctl(blkdev_fd, BLKGETSIZE64, &size_blkdev)) {
        printf("ioctl on %s failed - %s\n", argv[2], strerror(errno));
        goto end;
    }

    size_file = file_stbuf.st_size;

    if (size_file > size_blkdev) {
        printf("File %s (%ld) is bigger than block device %s (%ld)\n", argv[1], size_file, argv[2],
               size_blkdev);
        size_file = size_blkdev;
    }

    printf("Copying %ld bytes from %s to %s\n", size_file, argv[1], argv[2]);

    while (offset < size_file) {
        size_t blksize;
        char buf[BLK_SIZE];

        if ((size_file - offset) > BLK_SIZE) {
            blksize = BLK_SIZE;
        } else {
            blksize = 1;
        }

        if (read(file_fd, buf, blksize) != blksize) {
            printf("Error reading from %s - %s\n", argv[1], strerror(errno));
            goto end;
        }

        if (write(blkdev_fd, buf, blksize) != blksize) {
            printf("Error writing to %s - %s\n", argv[2], strerror(errno));
            goto end;
        }

        offset += blksize;
    }

    close(file_fd);
    file_fd = 0;
    close(blkdev_fd);
    blkdev_fd = 0;

    backup = malloc(strlen(argv[1]) + strlen(".bak"));
    if (backup == NULL) {
        printf("Error allocating memory - %s\n", strerror(errno));
        goto end;
    }

    snprintf(backup, strlen(argv[1]) + strlen(".bak"), "%s.%s", argv[1], "bak");
    rc = rename(argv[1], backup);
    if (rc < 0) {
        printf("Failed to rename %s to %s - %s\n", argv[1], backup, strerror(errno));
        goto end;
    }
    rc = symlink(argv[2], argv[1]);
    if (rc < 0) {
        printf("Failed to link %s to %s - %s\n", argv[2], argv[1], strerror(errno));
        goto end;
    }

    rc = unlink(backup);
    if (rc < 0) {
        printf("Failed to delete %s - %s\n", backup, strerror(errno));
        goto end;
    }

    rc = 0;

end:
    if (backup) {
        free(backup);
    }

    if (file_fd >= 0) {
        close(file_fd);
    }

    if (blkdev_fd >= 0) {
        close(blkdev_fd);
    }

    return rc;
}
