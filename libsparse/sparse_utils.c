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
#define _GNU_SOURCE /* for asprintf */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sparse/sparse.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "backed_block.h"
#include "sparse_file.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define MAX_PATH 4096

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define off64_t off_t
#endif

int img2simg(const char* input, const char* output) {
    return img2simg_size(input, output, 4096);
}

int img2simg_size(const char* input, const char* output, unsigned int block_size) {
    int in;
    int out;
    int ret;

    if (strcmp(input, "-") == 0) {
        in = STDIN_FILENO;
    } else {
        in = open(input, O_RDONLY | O_BINARY);
        if (in < 0) {
            fprintf(stderr, "Cannot open input file %s\n", input);
            return -1;
        }
    }

    if (strcmp(output, "-") == 0) {
        out = STDOUT_FILENO;
    } else {
        out = open(output, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
        if (out < 0) {
            fprintf(stderr, "Cannot open output file %s\n", output);
            if (in != STDIN_FILENO) {
                close(in);
            }
            return -1;
        }
    }

    ret = img2simg_size_fd(in, out, block_size);

    if (in != STDIN_FILENO) {
        close(in);
    }
    if (out != STDOUT_FILENO) {
        close(out);
    }

    return ret;
}

int img2simg_size_fd(int in, int out, int block_size) {
    struct sparse_file* s;
    off64_t len = lseek64(in, 0, SEEK_END);
    int ret;

    lseek64(in, 0, SEEK_SET);

    assert(block_size >= 1024);
    assert(block_size % 4 == 0);

    s = sparse_file_new(block_size, len);
    if (!s) {
       fprintf(stderr, "Failed to create sparse file\n");
       return -1;
    }

    sparse_file_verbose(s);
    ret = sparse_file_read(s, in, false, false);
    if (!ret) {
        ret = sparse_file_write(s, out, false, true, false);
        if (ret) {
            fprintf(stderr, "Failed to write sparse file\n");
        }
    } else {
        fprintf(stderr, "Failed to read file\n");
    }

    sparse_file_destroy(s);

    return ret;
}

int simg2img(int num_input, const char* input[], const char* output) {
    int* ifd = malloc(num_input * sizeof(*ifd));
    int ofd = -1;
    int i;
    int ret = -1;

    assert(ifd != NULL);
    for (i = 0; i < num_input; i++) {
        if (strcmp(input[i], "-") == 0) {
            ifd[i] = STDIN_FILENO;
        } else {
            ifd[i] = open(input[i], O_RDONLY | O_BINARY);
        }
        if (ifd[i] < 0) {
            fprintf(stderr, "Cannot open %s\n", input[i]);
            goto out;
        }
    }

    ofd = open(output, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
    if (ofd < 0) {
        fprintf(stderr, "Cannot open output file %s\n", output);
        goto out;
    }

    ret = simg2img_fd(num_input, ifd, ofd);

out:
    for (i = 0; i < num_input && ifd[i] >= 0; i++) {
        if (ifd[i] != STDIN_FILENO) {
            close(ifd[i]);
        }
    }
    free(ifd);

    if (ofd >= 0) {
        close(ofd);
    }
    return ret;
}

int simg2img_fd(int num_input, int* ifd, int ofd) {
    int i;

    for (i = 0; i < num_input; i++) {
        struct sparse_file* s = sparse_file_import(ifd[i], true, false);
        if (lseek(ofd, 0, SEEK_SET) < 0) {
            fprintf(stderr, "seek failed\n");
            sparse_file_destroy(s);
            return -1;
        }

        if (sparse_file_write(s, ofd, false, false, false) < 0) {
            fprintf(stderr, "Cannot write output file\n");
            sparse_file_destroy(s);
            return -1;
        }
        sparse_file_destroy(s);
    }

    return 0;
}

int append2simg(const char* output, const char* input) {
    int ofd;
    int ifd = -1;
    int tmpfd = -1;
    char* tmp_path = NULL;
    int ret = -1;

    ofd = open(output, O_RDWR | O_BINARY);
    if (ofd < 0) {
        fprintf(stderr, "Couldn't open output file (%s)\n", strerror(errno));
        return ret;
    }

    ifd = open(input, O_RDONLY | O_BINARY);
    if (ifd < 0) {
        fprintf(stderr, "Couldn't open input file (%s)\n", strerror(errno));
        goto fail;
    }

    ret = asprintf(&tmp_path, "%s.append2simg", output);
    if (ret < 0) {
        fprintf(stderr, "Couldn't allocate filename\n");
        goto fail;
    }
    tmpfd = open(tmp_path, O_WRONLY | O_CREAT | O_BINARY, 0664);
    if (tmpfd < 0) {
        fprintf(stderr, "Couldn't open temporary file (%s)\n", strerror(errno));
        ret = -1;
        goto fail;
    }
    ret = append2simg_fd(ofd, ifd, tmpfd);

fail:
    if (tmpfd >= 0) {
       close(tmpfd);
    }
    if (ifd >= 0) {
       close(ifd);
    }
    close(ofd);

    if (!ret) {
        ret = rename(tmp_path, output);
        if (ret < 0) {
            fprintf(stderr, "Failed to rename temporary file (%s)\n", strerror(errno));
        }
    } else {
        unlink(tmp_path);
    }
    if (tmp_path) {
        free(tmp_path);
    }
    return ret;
}
int append2simg_fd(int ofd, int ifd, int tmpfd) {
    struct sparse_file* s;
    off64_t input_len;
    int output_block;
    int ret;

    s = sparse_file_import_auto(ofd, false, true);
    if (!s) {
        fprintf(stderr, "Couldn't import output file\n");
        return -1;
    }

    input_len = lseek64(ifd, 0, SEEK_END);
    if (input_len < 0) {
        fprintf(stderr, "Couldn't get input file length (%s)\n", strerror(errno));
        sparse_file_destroy(s);
        return -1;
    } else if (input_len % s->block_size) {
        fprintf(stderr, "Input file is not a multiple of the output file's block size\n");
        sparse_file_destroy(s);
        return -1;
    }
    lseek64(ifd, 0, SEEK_SET);

    output_block = s->len / s->block_size;
    if (sparse_file_add_fd(s, ifd, 0, input_len, output_block) < 0) {
        fprintf(stderr, "Couldn't add input file\n");
        sparse_file_destroy(s);
        return -1;
    }
    s->len += input_len;

    lseek64(ofd, 0, SEEK_SET);
    ret = sparse_file_write(s, tmpfd, false, true, false);
    if (ret < 0) {
        fprintf(stderr, "Failed to write sparse file\n");
    }

    sparse_file_destroy(s);

    return ret;
}

int simg2simg(const char* input, const char* output, int64_t max_size) {
    int in;
    int out;
    int i;
    int ret = -1;
    struct sparse_file* s = NULL;
    struct sparse_file** out_s = NULL;
    int files;
    char filename[MAX_PATH];

    in = open(input, O_RDONLY | O_BINARY);
    if (in < 0) {
        fprintf(stderr, "Cannot open input file %s\n", input);
        return -1;
    }

    s = sparse_file_import(in, true, false);
    if (!s) {
        fprintf(stderr, "Failed to import sparse file\n");
        goto fail;
    }

    files = sparse_file_resparse(s, max_size, NULL, 0);
    if (files < 0) {
        fprintf(stderr, "Failed to resparse\n");
        goto fail;
    }

    out_s = calloc(sizeof(struct sparse_file*), files);
    assert(out_s != NULL);

    files = sparse_file_resparse(s, max_size, out_s, files);
    if (files < 0) {
        fprintf(stderr, "Failed to resparse\n");
        goto fail;
    }

    for (i = 0; i < files; i++) {
        ret = snprintf(filename, sizeof(filename), "%s.%d", output, i);
        if (ret >= (int)sizeof(filename)) {
            fprintf(stderr, "Filename too long\n");
            break;
        }

        out = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
        if (out < 0) {
            fprintf(stderr, "Cannot open output file %s\n", filename);
            break;
        }

        ret = sparse_file_write(out_s[i], out, false, true, false);
        close(out);
        if (ret) {
            fprintf(stderr, "Failed to write sparse file\n");
            break;
        }
    }

    for (i = 0; i < files; i++) {
        if (out_s[i]) {
            sparse_file_destroy(out_s[i]);
        }
    }

fail:
    if(out_s) {
        free(out_s);
    }
    if (s) {
        sparse_file_destroy(s);
    }
    close(in);

    return ret;
}
