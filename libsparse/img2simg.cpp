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

#include <private/sparse/sparse_utils.h>
#include <stdio.h>
#include <stdlib.h>

void usage() {
    fprintf(stderr, "Usage: img2simg <raw_image_file> <sparse_image_file> [<block_size>]\n");
}

int main(int argc, const char* argv[]) {
    unsigned int block_size = 4096;

    if (argc < 3 || argc > 4) {
        usage();
        return -1;
    }

    if (argc == 4) {
        block_size = atoi(argv[3]);
    }

    return img2simg(argv[1], argv[2], block_size);
}
