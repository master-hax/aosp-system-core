/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "fdevent.h"
#include "adb.h"

#include <linux/fb.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

/* TODO:
** - sync with vsync to avoid tearing
*/
/* This version number defines the format of the fbinfo struct.
   It must match versioning in ddms where this data is consumed. */
#define DDMS_RAWIMAGE_VERSION 1
struct fbinfo {
    unsigned int version;
    unsigned int bpp;
    unsigned int size;
    unsigned int width;
    unsigned int height;
    unsigned int red_offset;
    unsigned int red_length;
    unsigned int blue_offset;
    unsigned int blue_length;
    unsigned int green_offset;
    unsigned int green_length;
    unsigned int alpha_offset;
    unsigned int alpha_length;
} __attribute__((packed));

void framebuffer_service(int fd, void *cookie)
{
    struct fb_var_screeninfo vinfo;
    struct fb_fix_screeninfo finfo;
    int fb, offset;
    char *x = NULL;

    struct fbinfo fbinfo;
    unsigned i, bytespp;
    unsigned int fb_aligned_size;
    unsigned int fb_line_length;
    unsigned int fb_line_length_aligned;

    fb = open("/dev/graphics/fb0", O_RDONLY);
    if(fb < 0) goto done;

    /* Read fix screen info to take care of the case
     * when the line_length is aligned */
    if(ioctl(fb, FBIOGET_FSCREENINFO, &finfo) < 0) goto done;

    if(ioctl(fb, FBIOGET_VSCREENINFO, &vinfo) < 0) goto done;
    fcntl(fb, F_SETFD, FD_CLOEXEC);

    bytespp = vinfo.bits_per_pixel / 8;

    fbinfo.version = DDMS_RAWIMAGE_VERSION;
    fbinfo.bpp = vinfo.bits_per_pixel;
    fbinfo.size = vinfo.xres * vinfo.yres * bytespp;
    fbinfo.width = vinfo.xres;
    fbinfo.height = vinfo.yres;
    fbinfo.red_offset = vinfo.red.offset;
    fbinfo.red_length = vinfo.red.length;
    fbinfo.green_offset = vinfo.green.offset;
    fbinfo.green_length = vinfo.green.length;
    fbinfo.blue_offset = vinfo.blue.offset;
    fbinfo.blue_length = vinfo.blue.length;
    fbinfo.alpha_offset = vinfo.transp.offset;
    fbinfo.alpha_length = vinfo.transp.length;

     x = (char*)malloc(finfo.line_length);
     if (x == NULL) goto done;

     /* Line length without possible extra bytes for alignment */
     fb_line_length = vinfo.xres * bytespp;

     /* Aligned line length due to hardware requirement */
     fb_line_length_aligned = finfo.line_length;

    /* HACK: for several of our 3d cores a specific alignment
     * is required so the start of the fb may not be an integer number of lines
     * from the base.  As a result we are storing the additional offset in
     * xoffset. This is not the correct usage for xoffset, it should be added
     * to each line, not just once at the beginning */
    offset = vinfo.xoffset * bytespp;

    /* Take line alignment into account when calculating offset */
    offset += fb_line_length_aligned * vinfo.yoffset;

    if(writex(fd, &fbinfo, sizeof(fbinfo))) goto done;

    lseek(fb, offset, SEEK_SET);
    fb_aligned_size = finfo.line_length*vinfo.yres;

    for(i = 0; i < fb_aligned_size; i += fb_line_length_aligned) {
      /* Read one line including alignment bytes */
      if(readx(fb, x, fb_line_length_aligned)) goto done;
      /* Write one line, but skip extra bytes added for alignment */
      if(writex(fd, x, fb_line_length)) goto done;
    }

done:
    if(fb >= 0) close(fb);
    close(fd);
    free(x);
}
