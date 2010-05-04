/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <stdio.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"
#include "adb_client.h"
#include "framebuffer.h"

#include <png.h>

#if ADB_HOST

#define PIXEL_VALUE(value, fbinfo, type) ((value >> fbinfo.type##_offset) & \
        ((1 << (fbinfo.type##_length + 1)) - 1)) << (8 - fbinfo.type##_length)

static void deallocate_rows(png_bytepp rows, int numRows) {
    if (rows == NULL) {
        return;
    }

    int i;
    for (i = 0; i < numRows; i++) {
        if (rows[i] != NULL) {
            free(rows[i]);
        }
    }

    free(rows);
}

static png_bytepp allocate_rows(int numRows, int rowSize) {
    png_bytepp rows = (png_bytepp)calloc(numRows, png_sizeof(png_bytep));
    if (rows == NULL) {
        fprintf(stderr, "error: allocation failed for row pointer array\n");
        return NULL;
    }

    int i;
    for (i = 0; i < numRows; i++) {
        rows[i] = (png_bytep)malloc(rowSize);
        if (rows[i] == NULL) {
            fprintf(stderr, "error: allocation failed for row %d\n", i);
            deallocate_rows(rows, numRows);
            return NULL;
        }
    }

    return rows;
}

static int setup_png_write_struct(png_structp* png_ptr, png_infop* info_ptr) {
    *png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, 0,
            (png_error_ptr)NULL,
            (png_error_ptr)NULL);
    if (!*png_ptr) {
        fprintf(stderr, "error: creating PNG write struct\n");
        return -1;
    }

    if (setjmp(png_jmpbuf(*png_ptr))) {
        fprintf(stderr, "error: setting PNG jumps\n");
        png_destroy_write_struct(png_ptr, info_ptr);
        return -1;
    }

    *info_ptr = png_create_info_struct(*png_ptr);
    if (!*info_ptr) {
        fprintf(stderr, "error: creating PNG info struct\n");
        png_destroy_write_struct(png_ptr, info_ptr);
        return -1;
    }

    return 0;
}

int adb_screenshot(int argc, char **argv) {
    unsigned int i;
    struct fbinfo fbinfo;
    int ret = -1;
    char* filename = "screenshot.png";

    if (argc > 0) {
        filename = *argv;
    }

    FILE* fp = fopen(filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "error: couldn't open file for writing: %s\n", filename);
        return ret;
    }

    int adb_fd = adb_connect("framebuffer:");
    if (adb_fd < 0) {
        fprintf(stderr, "error: unable to connect to ADB\n");
        fclose(fp);
        return ret;
    }

    if(readx(adb_fd, &fbinfo, sizeof(fbinfo))) {
        fprintf(stderr, "error: reading framebuffer info from ADB\n");
        adb_close(adb_fd);
        fclose(fp);
        return ret;
    }

    const int bytepp = fbinfo.bpp / 8;
    const int stride = fbinfo.width * bytepp;
    png_bytepp rows = allocate_rows((int) fbinfo.height, stride);

    char buf[stride];
    for (i = 0; i < fbinfo.height; i++) {
        if(readx(adb_fd, &buf, stride)) {
            if(errno == EINTR) continue;
            fprintf(stderr, "error reading ADB socket: %s\n", strerror(errno));
            goto error;
        }

        int pixel;
        for (pixel = 0; pixel < stride; pixel += bytepp) {
            unsigned int value;
            if (fbinfo.bpp == 16) {
                value = ((buf[pixel+1] & 0xFF) << 8) |
                        (buf[pixel] & 0xFF);
            } else if (fbinfo.bpp == 32) {
                value = ((buf[pixel+3] & 0xFF) << 24) |
                        ((buf[pixel+2] & 0xFF) << 16) |
                        ((buf[pixel+1] & 0xFF) << 8) |
                        (buf[pixel] & 0xFF);
            } else {
                fprintf(stderr, "error: unsupported bitdepth %d\n", fbinfo.bpp);
                goto error;
            }

            rows[i][pixel] = PIXEL_VALUE(value, fbinfo, red);
            rows[i][pixel+1] = PIXEL_VALUE(value, fbinfo, green);
            rows[i][pixel+2] = PIXEL_VALUE(value, fbinfo, blue);

            if (fbinfo.alpha_length == 0) {
                rows[i][pixel+3] = 0xFF;
            } else {
                rows[i][pixel+3] = PIXEL_VALUE(value, fbinfo, alpha);
            }
        }
    }

    png_structp png_ptr = NULL;
    png_infop info_ptr = NULL;

    if (setup_png_write_struct(&png_ptr, &info_ptr) != 0) {
        goto error;
    }

    png_set_IHDR(png_ptr, info_ptr,
            fbinfo.width, fbinfo.height, fbinfo.bpp / 4,
            PNG_COLOR_TYPE_RGB_ALPHA,
            PNG_INTERLACE_NONE,
            PNG_COMPRESSION_TYPE_DEFAULT,
            PNG_FILTER_TYPE_DEFAULT);

    png_init_io(png_ptr, fp);
    png_set_filter(png_ptr, 0, PNG_ALL_FILTERS);
    png_write_info(png_ptr, info_ptr);
    png_write_image(png_ptr, rows);
    png_write_end(png_ptr, info_ptr);

    fflush(fp);

    printf("Wrote %d byte screenshot (%dx%d, %d bpp) to: %s\n",
            fbinfo.size, fbinfo.width, fbinfo.height, fbinfo.bpp, filename);

    ret = 0;

error:
    png_destroy_write_struct(&png_ptr, &info_ptr);
    deallocate_rows(rows, (int) fbinfo.height);
    adb_close(adb_fd);
    fclose(fp);

    return ret;
}

#endif /* ADB_HOST */
