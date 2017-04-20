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

#ifndef _LIBSPARSE_SPARSE_UTILS_H_
#define _LIBSPARSE_SPARSE_UTILS_H_

#include <stdbool.h>
#include <stdint.h>

#include <sparse/sparse.h>

/**
 * img2simg - Convert a normal file into a sparse file with 4K block size
 *
 * @input : input (normal) path
 * @output : output (sparse) path
 * @block_size : Minimum chunk size
 *
 * Converts a normal file into a sparse file.  Returns 0 on success, -errno on
 * error.
 */
int img2simg(const char *input, const char *output, unsigned int block_size = 4096);

/**
 * img2simg_fd - Convert a normal file into a sparse file
 *
 * @in : input (normal) file descriptor
 * @out : output (sparse) file descriptor
 * @block_size : Minimum chunk size
 *
 * Converts a normal file into a sparse file.  Returns 0 on success, -errno on
 * error.
 */
int img2simg_fd(int in, int out, unsigned int block_size = 4096);

/**
 * simg2img - Convert some sparse files into a normal file
 *
 * @num_input : number of input files
 * @input : array of sparse file paths for input
 * @output : output path
 *
 * simg2img takes multiple input sparse files, and writes the result
 * to a normal (unsparse) file at output.  Returns 0 on success, -errno on
 * error.
 */
int simg2img(int num_input, const char *input[], const char *output);

/**
 * simg2img_fd - Convert some sparse files into a normal file
 *
 * @num_input : number of input files
 * @input : array of sparse fds for input
 * @output : output file descriptor
 *
 * simg2img_fd takes multiple input sparse files, and writes the result
 * to a normal (unsparse) file at output.  Returns 0 on success, -errno on
 * error.
 */
int simg2img_fd(int num_input, int ifd[], int ofd);

/**
 * append2simg - Append data to the end of a sparse image
 *
 * @output : output path (sparse file to be appended)
 * @input : path of file to append
 *
 * append2simg takes a single input file (sized as a multiple of block_size)
 * and appends it to sparse output.  Returns 0 on success, -errno on error.
 */
int append2simg(const char *output, const char *input);

/**
 * append2simg_fd - Append data to the end of a sparse image
 *
 * @ofd : output file descriptor (sparse file to be appended)
 * @ifd : file descriptor of file to append
 * @tmpfd : descriptor of temporary (read/write) file
 *
 * append2simg_fd takes a single input file (sized as a multiple of block_size)
 * and appends it to sparse output.  append2simg_fd also requires a tmpfile
 * to be created and passed in as a file descriptor.
 *
 * Returns 0 on success, -errno on error.
 */
int append2simg_fd(int ofd, int ifd, int tmpfd);

/**
 * simg2simg - Resparse a sparse file into smaller files
 *
 * @input : path to sparse input file
 * @output : base file path for multiple sparse output files
 * @max_size : maximum file size
 *
 *  Takes input file, output base path, and max_size, and outputs
 *  files prefixed by the passed output base path.
 *
 *  Returns number of output files on success, -errno on error.
 */
int simg2simg(const char* input, const char* output, int64_t max_size);

#endif
