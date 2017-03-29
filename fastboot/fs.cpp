#include "fs.h"

#include "fastboot.h"
#include "make_f2fs.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <ext4_utils/ext4_utils.h>
#include <ext4_utils/make_ext4fs.h>
#include <sparse/sparse.h>

static void fs_reset_ext4fs_info() {
	// Reset all the global data structures used by make_ext4fs so it
	// can be called again.
	memset(&info, 0, sizeof(info));
	memset(&aux_info, 0, sizeof(aux_info));

	if (ext4_sparse_file) {
		sparse_file_destroy(ext4_sparse_file);
		ext4_sparse_file = NULL;
	}
}

static int fs_make_ext4fs_sparse_fd_directory_align(int fd, const char *label, long long len,
				const char *mountpoint, struct selabel_handle *sehnd,
				const char *directory, unsigned eraseblk, unsigned logicalblk)
{
	fs_reset_ext4fs_info();
	info.len = len;
	info.label = label;
	info.flash_erase_block_size = eraseblk;
	info.flash_logical_block_size = logicalblk;

	return make_ext4fs_internal(fd, directory, NULL, mountpoint, NULL,
								0, 1, 0, 0, 0,
								sehnd, 0, -1, NULL, NULL, NULL);
}

static int fs_make_ext4fs_sparse_fd_align(int fd, const char *label, long long len,
				const char *mountpoint, struct selabel_handle *sehnd,
				unsigned eraseblk, unsigned logicalblk)
{
	return fs_make_ext4fs_sparse_fd_directory_align(fd, label, len, mountpoint, sehnd, NULL,
								eraseblk, logicalblk);
}

static int generate_ext4_image(const char* label, int fd, long long partSize, const std::string& initial_dir,
                                       unsigned eraseBlkSize, unsigned logicalBlkSize)
{
    if (initial_dir.empty()) {
        fs_make_ext4fs_sparse_fd_align(fd, label, partSize, NULL, NULL, eraseBlkSize, logicalBlkSize);
    } else {
        fs_make_ext4fs_sparse_fd_directory_align(fd, label, partSize, NULL, NULL, initial_dir.c_str(),
                                              eraseBlkSize, logicalBlkSize);
    }
    return 0;
}

#ifdef USE_F2FS
static int generate_f2fs_image(const char* label, int fd, long long partSize, const std::string& initial_dir,
                               unsigned /* unused */, unsigned /* unused */)
{
    info.label = label;
    if (!initial_dir.empty()) {
        fprintf(stderr, "Unable to set initial directory on F2FS filesystem\n");
        return -1;
    }
    return make_f2fs_sparse_fd(fd, partSize, NULL, NULL);
}
#endif

static const struct fs_generator {
    const char* fs_type;  //must match what fastboot reports for partition type

    //returns 0 or error value
    int (*generate)(const char* label, int fd, long long partSize, const std::string& initial_dir,
                    unsigned eraseBlkSize, unsigned logicalBlkSize);

} generators[] = {
    { "ext4", generate_ext4_image},
#ifdef USE_F2FS
    { "f2fs", generate_f2fs_image},
#endif
};

const struct fs_generator* fs_get_generator(const std::string& fs_type) {
    for (size_t i = 0; i < sizeof(generators) / sizeof(*generators); i++) {
        if (fs_type == generators[i].fs_type) {
            return generators + i;
        }
    }
    return nullptr;
}

int fs_generator_generate(const struct fs_generator* gen, const char* label, int tmpFileNo, long long partSize,
    const std::string& initial_dir, unsigned eraseBlkSize, unsigned logicalBlkSize)
{
    return gen->generate(label, tmpFileNo, partSize, initial_dir, eraseBlkSize, logicalBlkSize);
}
