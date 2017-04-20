/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sparse/sparse.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define lseek64 lseek
#define off64_t off_t
#endif

void usage() {
    fprintf(stderr, "Usage: img2simg <raw_image_file> <sparse_image_file> [<block_size>]\n");
}

/* todo: migrate img2simg.c */

int main(int argc, char* argv[]) {
    int in;
    int out;
    int ret;
    struct sparse_file* s;
    unsigned int block_size = 4096;
    off64_t len;

    if (argc < 3 || argc > 4) {
        usage();
        exit(-1);
    }

    if (argc == 4) {
        block_size = atoi(argv[3]);
    }

    if (block_size < 1024 || block_size % 4 != 0) {
        usage();
        exit(-1);
    }

    if (strcmp(argv[1], "-") == 0) {
        in = STDIN_FILENO;
    } else {
        in = open(argv[1], O_RDONLY | O_BINARY);
        if (in < 0) {
            fprintf(stderr, "Cannot open input file %s\n", argv[1]);
            exit(-1);
        }
    }

    if (strcmp(argv[2], "-") == 0) {
        out = STDOUT_FILENO;
    } else {
        out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
        if (out < 0) {
            fprintf(stderr, "Cannot open output file %s\n", argv[2]);
            exit(-1);
        }
    }

    len = lseek64(in, 0, SEEK_END);
    lseek64(in, 0, SEEK_SET);

    s = sparse_file_new(block_size, len);
    if (!s) {
        fprintf(stderr, "Failed to create sparse file\n");
        exit(-1);
    }

    sparse_file_verbose(s);
    ret = sparse_file_read(s, in, false, false);
    if (ret) {
        fprintf(stderr, "Failed to read file\n");
        exit(-1);
    }

    ret = sparse_file_write(s, out, false, true, false);
    if (ret) {
        fprintf(stderr, "Failed to write sparse file\n");
        exit(-1);
    }

    close(in);
    close(out);

    exit(0);
}

void usage() {
    fprintf(stderr, "Usage: simg2img <sparse_image_files> <raw_image_file>\n");
}

/* todo: migrate simg2img.c */

int main(int argc, char* argv[]) {
    int in;
    int out;
    int i;
    struct sparse_file* s;

    if (argc < 3) {
        usage();
        exit(-1);
    }

    out = open(argv[argc - 1], O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
    if (out < 0) {
        fprintf(stderr, "Cannot open output file %s\n", argv[argc - 1]);
        exit(-1);
    }

    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-") == 0) {
            in = STDIN_FILENO;
        } else {
            in = open(argv[i], O_RDONLY | O_BINARY);
            if (in < 0) {
                fprintf(stderr, "Cannot open input file %s\n", argv[i]);
                exit(-1);
            }
        }

        s = sparse_file_import(in, true, false);
        if (!s) {
            fprintf(stderr, "Failed to read sparse file\n");
            exit(-1);
        }

        if (lseek(out, 0, SEEK_SET) == -1) {
            perror("lseek failed");
            exit(EXIT_FAILURE);
        }

        if (sparse_file_write(s, out, false, false, false) < 0) {
            fprintf(stderr, "Cannot write output file\n");
            exit(-1);
        }
        sparse_file_destroy(s);
        close(in);
    }

    close(out);

    exit(0);
}

void usage() {
    fprintf(stderr, "Usage: append2simg <output> <input>\n");
}

/* todo: migrate append2simg.c */

int main(int argc, char* argv[]) {
    int output;
    int output_block;
    char* output_path;
    struct sparse_file* sparse_output;

    int input;
    char* input_path;
    off64_t input_len;

    int tmp_fd;
    char* tmp_path;

    int ret;

    if (argc == 3) {
        output_path = argv[1];
        input_path = argv[2];
    } else {
        usage();
        exit(-1);
    }

    ret = asprintf(&tmp_path, "%s.append2simg", output_path);
    if (ret < 0) {
        fprintf(stderr, "Couldn't allocate filename\n");
        exit(-1);
    }

    output = open(output_path, O_RDWR | O_BINARY);
    if (output < 0) {
        fprintf(stderr, "Couldn't open output file (%s)\n", strerror(errno));
        exit(-1);
    }

    sparse_output = sparse_file_import_auto(output, false, true);
    if (!sparse_output) {
        fprintf(stderr, "Couldn't import output file\n");
        exit(-1);
    }

    input = open(input_path, O_RDONLY | O_BINARY);
    if (input < 0) {
        fprintf(stderr, "Couldn't open input file (%s)\n", strerror(errno));
        exit(-1);
    }

    input_len = lseek64(input, 0, SEEK_END);
    if (input_len < 0) {
        fprintf(stderr, "Couldn't get input file length (%s)\n", strerror(errno));
        exit(-1);
    } else if (input_len % sparse_output->block_size) {
        fprintf(stderr, "Input file is not a multiple of the output file's block size");
        exit(-1);
    }
    lseek64(input, 0, SEEK_SET);

    output_block = sparse_output->len / sparse_output->block_size;
    if (sparse_file_add_fd(sparse_output, input, 0, input_len, output_block) < 0) {
        fprintf(stderr, "Couldn't add input file\n");
        exit(-1);
    }
    sparse_output->len += input_len;

    tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_BINARY, 0664);
    if (tmp_fd < 0) {
        fprintf(stderr, "Couldn't open temporary file (%s)\n", strerror(errno));
        exit(-1);
    }

    lseek64(output, 0, SEEK_SET);
    if (sparse_file_write(sparse_output, tmp_fd, false, true, false) < 0) {
        fprintf(stderr, "Failed to write sparse file\n");
        exit(-1);
    }

    sparse_file_destroy(sparse_output);
    close(tmp_fd);
    close(output);
    close(input);

    ret = rename(tmp_path, output_path);
    if (ret < 0) {
        fprintf(stderr, "Failed to rename temporary file (%s)\n", strerror(errno));
        exit(-1);
    }

    free(tmp_path);

    exit(0);
}

void usage() {
    fprintf(stderr, "Usage: simg2simg <sparse image file> <sparse_image_file> <max_size>\n");
}

/* todo: migrate simg2simg.c */

int main(int argc, char* argv[]) {
    int in;
    int out;
    int i;
    int ret;
    struct sparse_file* s;
    int64_t max_size;
    struct sparse_file** out_s;
    int files;
    char filename[4096];

    if (argc != 4) {
        usage();
        exit(-1);
    }

    max_size = atoll(argv[3]);

    in = open(argv[1], O_RDONLY | O_BINARY);
    if (in < 0) {
        fprintf(stderr, "Cannot open input file %s\n", argv[1]);
        exit(-1);
    }

    s = sparse_file_import(in, true, false);
    if (!s) {
        fprintf(stderr, "Failed to import sparse file\n");
        exit(-1);
    }

    files = sparse_file_resparse(s, max_size, NULL, 0);
    if (files < 0) {
        fprintf(stderr, "Failed to resparse\n");
        exit(-1);
    }

    out_s = calloc(sizeof(struct sparse_file*), files);
    if (!out_s) {
        fprintf(stderr, "Failed to allocate sparse file array\n");
        exit(-1);
    }

    files = sparse_file_resparse(s, max_size, out_s, files);
    if (files < 0) {
        fprintf(stderr, "Failed to resparse\n");
        exit(-1);
    }

    for (i = 0; i < files; i++) {
        ret = snprintf(filename, sizeof(filename), "%s.%d", argv[2], i);
        if (ret >= (int)sizeof(filename)) {
            fprintf(stderr, "Filename too long\n");
            exit(-1);
        }

        out = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
        if (out < 0) {
            fprintf(stderr, "Cannot open output file %s\n", argv[2]);
            exit(-1);
        }

        ret = sparse_file_write(out_s[i], out, false, true, false);
        if (ret) {
            fprintf(stderr, "Failed to write sparse file\n");
            exit(-1);
        }
        close(out);
    }

    close(in);

    exit(0);
}
