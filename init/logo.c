/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/fb.h>
#include <linux/kd.h>

#include "log.h"

#ifdef ANDROID
#include <cutils/memory.h>
#else
void android_memset16(void *_ptr, unsigned short val, unsigned count)
{
    unsigned short *ptr = _ptr;
    count >>= 1;
    while(count--)
        *ptr++ = val;
}
#endif

struct FB {
    unsigned char *bits;
    unsigned size;
    int fd;
    struct fb_fix_screeninfo fi;
    struct fb_var_screeninfo vi;
};

#define fb_width(fb) ((fb)->vi.xres)
#define fb_height(fb) ((fb)->vi.yres)
#define fb_bytes_pixel(fb) ((fb)->vi.bits_per_pixel >> 3)
#define fb_size(fb) ((fb)->fi.line_length * fb_height(fb))
#define fb_stride(fb) ((fb)->fi.line_length / fb_bytes_pixel(fb))

static inline uint8_t getbits(uint16_t bits, int start, int size)
{
    return (bits & (((1 << size) - 1) << start)) >> start;
}

/* Fill in bottom bits with a repeat of the high bits,
 * instead of just 0 */
static inline uint8_t five_to_eight(uint8_t x)
{
    return (x << 3) | (x >> 2);
}

static inline uint8_t six_to_eight(uint8_t x)
{
    return (x << 2) | (x >> 4);
}

static inline uint32_t conv565_8888(uint16_t pix)
{
    int red, green, blue;

    red = getbits(pix, 11, 5);
    green = getbits(pix, 5, 6);
    blue = getbits(pix, 0, 5);

    return (five_to_eight(red) << 16) +
        (six_to_eight(green) << 8) +
        five_to_eight(blue);
}

static int fb_open(struct FB *fb)
{
    fb->fd = open("/dev/graphics/fb0", O_RDWR);
    if (fb->fd < 0)
        return -1;

    if (ioctl(fb->fd, FBIOGET_FSCREENINFO, &fb->fi) < 0)
        goto fail;
    if (ioctl(fb->fd, FBIOGET_VSCREENINFO, &fb->vi) < 0)
        goto fail;

    fb->bits = mmap(0, fb_size(fb), PROT_READ | PROT_WRITE, 
                    MAP_SHARED, fb->fd, 0);
    if (fb->bits == MAP_FAILED)
        goto fail;

    return 0;

fail:
    close(fb->fd);
    return -1;
}

static void fb_close(struct FB *fb)
{
    munmap(fb->bits, fb_size(fb));
    close(fb->fd);
}

/* there's got to be a more portable way to do this ... */
static void fb_update(struct FB *fb)
{
    fb->vi.yoffset = 1;
    ioctl(fb->fd, FBIOPUT_VSCREENINFO, &fb->vi);
    fb->vi.yoffset = 0;
    ioctl(fb->fd, FBIOPUT_VSCREENINFO, &fb->vi);
}

static int vt_set_mode(int graphics)
{
    int fd, r;
    fd = open("/dev/tty0", O_RDWR | O_SYNC);
    if (fd < 0)
        return -1;
    r = ioctl(fd, KDSETMODE, (void*) (graphics ? KD_GRAPHICS : KD_TEXT));
    close(fd);
    return r;
}

/* 565RLE image format: [count(2 bytes), rle(2 bytes)] */

int load_565rle_image(char *fn)
{
    struct FB fb;
    struct stat s;
    unsigned short *data, *ptr;
    uint8_t *bits;
    unsigned count, max, padding, hloc;
    int fd;

    if (vt_set_mode(1)) 
        return -1;

    fd = open(fn, O_RDONLY);
    if (fd < 0) {
        ERROR("cannot open '%s'\n", fn);
        goto fail_restore_text;
    }

    if (fstat(fd, &s) < 0) {
        goto fail_close_file;
    }

    data = mmap(0, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED)
        goto fail_close_file;

    if (fb_open(&fb))
        goto fail_unmap_data;
    max = fb_width(&fb) * fb_height(&fb);
    ptr = data;
    count = s.st_size;
    bits = fb.bits;
    padding = fb_stride(&fb) - fb_width(&fb);
    hloc = 0;

    while (count > 3) {
        unsigned n = ptr[0];
        if (n > max)
            break;
        max -= n;

        while (n) {
            unsigned remaining_pixels = fb_width(&fb) - hloc;
            unsigned pix_to_write = (remaining_pixels < n) ? remaining_pixels : n;
            switch (fb_bytes_pixel(&fb)) {
            case 2:
                android_memset16((uint16_t *)bits, ptr[1], pix_to_write << 1);
                break;
            case 4:
                android_memset32((uint32_t *)bits, conv565_8888(ptr[1]),
                        pix_to_write << 2);
                break;
            }
            bits += pix_to_write * fb_bytes_pixel(&fb);

            if (pix_to_write != n) {
                /* Wrapping around, skipping any padding */
                bits += padding * fb_bytes_pixel(&fb);
                n -= pix_to_write;
                hloc = 0;
            } else {
                hloc += pix_to_write;
                break;
            }
        }

        ptr += 2;
        count -= 4;
    }

    munmap(data, s.st_size);
    fb_update(&fb);
    fb_close(&fb);
    close(fd);
    unlink(fn);
    return 0;

fail_unmap_data:
    munmap(data, s.st_size);    
fail_close_file:
    close(fd);
fail_restore_text:
    vt_set_mode(0);
    return -1;
}

