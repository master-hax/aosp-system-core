/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "backed_block.h"
#include "private/sparse/sparse_utils.h"
#include "sparse/sparse.h"
#include "sparse_file.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define off64_t off_t
#endif
typedef std::unique_ptr<struct sparse_file, decltype(&sparse_file_destroy)> unique_sparse_file_p;

/* todo: migrate img2simg.c */

int img2simg(const char* input, const char* output, unsigned int block_size) {
    int in;
    int out;
    android::base::unique_fd unique_fdin, unique_fdout;

    if (strcmp(input, "-") == 0) {
        in = STDIN_FILENO;
    } else {
        unique_fdin.reset(open(input, O_RDONLY | O_BINARY));
        in = unique_fdin;
        if (in < 0) {
            LOG(ERROR) << "Cannot open input file " << input << " : " << strerror(errno);
            return -errno;
        }
    }

    if (strcmp(output, "-") == 0) {
        out = STDOUT_FILENO;
    } else {
        unique_fdout.reset(open(output, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664));
        out = unique_fdout;
        if (out < 0) {
            LOG(ERROR) << "Cannot open output file " << output << " : " << strerror(errno);
            return -errno;
        }
    }

    return img2simg_fd(in, out, block_size);
}

int img2simg_fd(int in, int out, unsigned int block_size) {
    assert(block_size >= 1024);
    assert(block_size % 4 == 0);

    off64_t len = lseek64(in, 0, SEEK_END);
    lseek64(in, 0, SEEK_SET);

    unique_sparse_file_p s(sparse_file_new(block_size, len), sparse_file_destroy);

    if (!s) {
        LOG(ERROR) << "Failed to create sparse file : " << strerror(errno);
        return -errno;
    }

    sparse_file_verbose(s.get());
    int ret = sparse_file_read(s.get(), in, false, false);
    if (!ret) {
        ret = sparse_file_write(s.get(), out, false, true, false);
        if (ret) {
            LOG(ERROR) << "Failed to write sparse file : " << strerror(errno);
        }
    } else {
        LOG(ERROR) << "Failed to read file : " << strerror(errno);
    }

    return ret;
}

/* todo: migrate simg2img.c */

int simg2img(int num_input, const char* input[], const char* output) {
    int ifd[num_input];
    android::base::unique_fd unique_ifd[num_input];

    android::base::unique_fd ofd(open(output, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664));
    if (ofd < 0) {
        LOG(ERROR) << "Cannot open output file" << output << " : " << strerror(errno);
        return -errno;
    }

    assert(ifd != NULL);
    for (int i = 0; i < num_input; i++) {
        if (strcmp(input[i], "-") == 0) {
            ifd[i] = STDIN_FILENO;
        } else {
            unique_ifd[i].reset(open(input[i], O_RDONLY | O_BINARY));
            ifd[i] = unique_ifd[i];
        }
        if (ifd[i] < 0) {
            LOG(ERROR) << "Cannot open " << input[i] << " : " << strerror(errno);
            return -errno;
        }
    }

    return simg2img_fd(num_input, ifd, ofd);
}

int simg2img_fd(int num_input, int ifd[], int ofd) {
    for (int i = 0; i < num_input; i++) {
        unique_sparse_file_p s(sparse_file_import(ifd[i], true, false), sparse_file_destroy);
        if (lseek(ofd, 0, SEEK_SET) < 0) {
            LOG(ERROR) << "seek failed : " << strerror(errno);
            return -errno;
        }

        int ret = sparse_file_write(s.get(), ofd, false, false, false);
        if (ret < 0) {
            LOG(ERROR) << "Cannot write output file";
            return ret;
        }
    }

    return 0;
}

/* todo: migrate append2simg.c */

int append2simg(const char* output, const char* input) {
    android::base::unique_fd ofd(open(output, O_RDWR | O_BINARY));

    if (ofd < 0) {
        LOG(ERROR) << "Couldn't open output file " << output << " : " << strerror(errno);
        return -errno;
    }

    android::base::unique_fd ifd(open(input, O_RDONLY | O_BINARY));
    if (ifd < 0) {
        LOG(ERROR) << "Couldn't open input file" << input << " : " << strerror(errno);
        return -errno;
    }

    std::string tmp_path = android::base::StringPrintf("%s.append2simg", output);

    android::base::unique_fd tmpfd(open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_BINARY, 0664));
    if (tmpfd < 0) {
        LOG(ERROR) << "Couldn't open temporary file " << tmp_path << " : " << strerror(errno);
        return -errno;
    }
    int ret = append2simg_fd(ofd, ifd, tmpfd);

    if (!ret) {
        ret = rename(tmp_path.c_str(), output);
        if (ret < 0) {
            LOG(ERROR) << "Failed to rename temporary file " << strerror(errno);
        }
    }
    android::base::RemoveFileIfExists(tmp_path, NULL);

    return ret;
}

int append2simg_fd(int ofd, int ifd, int tmpfd) {
    unique_sparse_file_p s(sparse_file_import_auto(ofd, false, true), sparse_file_destroy);
    if (!s) {
        LOG(ERROR) << "Couldn't import output file";
        return -EINVAL;
    }

    off64_t input_len = lseek64(ifd, 0, SEEK_END);
    if (input_len < 0) {
        LOG(ERROR) << "Couldn't get input file length : " << strerror(errno);
        return -errno;
    } else if (input_len % s->block_size) {
        LOG(ERROR) << "Input file is not a multiple of the output file's block size";
        return -EINVAL;
    }
    lseek64(ifd, 0, SEEK_SET);

    int output_block = s->len / s->block_size;
    int ret = sparse_file_add_fd(s.get(), ifd, 0, input_len, output_block);
    if (ret < 0) {
        LOG(ERROR) << "Couldn't add input file";
        return ret;
    }
    s->len += input_len;

    lseek64(ofd, 0, SEEK_SET);
    ret = sparse_file_write(s.get(), tmpfd, false, true, false);
    if (ret < 0) {
        LOG(ERROR) << "Failed to write sparse file";
    }

    return ret;
}

/* todo: migrate simg2simg.c */

int simg2simg(const char* input, const char* output, int64_t max_size) {
    android::base::unique_fd in(open(input, O_RDONLY | O_BINARY));
    if (in < 0) {
        LOG(ERROR) << "Cannot open input file" << input << " : " << strerror(errno);
        return -errno;
    }

    unique_sparse_file_p s(sparse_file_import(in, true, false), sparse_file_destroy);
    if (!s) {
        LOG(ERROR) << "Failed to import sparse file";
        return -EINVAL;
    }

    int files = sparse_file_resparse(s.get(), max_size, NULL, 0);
    if (files < 0) {
        LOG(ERROR) << "Failed to resparse";
        return files;
    }

    struct sparse_file* out_s[files];

    files = sparse_file_resparse(s.get(), max_size, out_s, files);
    if (files < 0) {
        LOG(ERROR) << "Failed to resparse";
        return files;
    }

    int ret = 0;
    for (int i = 0; i < files; i++) {
        std::string filename = android::base::StringPrintf("%s.%d", output, i);
        android::base::unique_fd out(
            open(filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664));
        if (out < 0) {
            ret = -errno;
            LOG(ERROR) << "Cannot open output file " << filename << " : " << strerror(errno);
            break;
        }

        ret = sparse_file_write(out_s[i], out, false, true, false);
        if (ret) {
            LOG(ERROR) << "Failed to write sparse file";
            break;
        }
    }

    for (int i = 0; i < files; i++) {
        sparse_file_destroy(out_s[i]);
    }

    if (!ret) return files;
    return ret;
}
