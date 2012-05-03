/* tools/mkenviroimg/mkenviroimg.c
**
** Copyright 2007, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "mincrypt/sha.h"
#include "enviroimg.h"

static void *load_file(const char *fn, unsigned *_sz)
{
    char *data;
    int sz;
    int fd;

    data = 0;
    fd = open(fn, O_RDONLY);
    if(fd < 0) return 0;

    sz = lseek(fd, 0, SEEK_END);
    if(sz < 0) goto oops;

    if(lseek(fd, 0, SEEK_SET) != 0) goto oops;

    data = (char*) malloc(sz);
    if(data == 0) goto oops;

    if(read(fd, data, sz) != sz) goto oops;

    close(fd);

    if(_sz) *_sz = sz;
    return data;

oops:
    close(fd);
    if(data != 0) free(data);
    return 0;
}

static int usage(void)
{
    fprintf(stderr,"usage: mkenviroimg\n"
            "       --dev_tree <filename>\n"
            "       --dt_base <Load address of device tree>\n"
            "       --enviroment <default enviroment data in binary format>\n"
            "       --env_size <size>\n"
            "       --board <board name limited to %i characters>\n"
            "       --splash_img <splash image-filename>\n"
            "       --fastboot_img <fastboot image-filename>\n"
            "       --charger_img <charger image-filename>\n"
            "       --fb_base <Framebuffer address for the image>\n"
            "       -o | --output <filename>\n", ENVIRO_NAME_SIZE
            );
    return 1;
}



static unsigned char padding[4096] = { 0, };

static int write_padding(int fd, unsigned pagesize, unsigned itemsize)
{
    unsigned pagemask = pagesize - 1;
    unsigned count;

    if((itemsize & pagemask) == 0) {
        return 0;
    }

    count = pagesize - (itemsize & pagemask);

    if(write(fd, padding, count) != count) {
        return -1;
    } else {
        return 0;
    }
}

static int write_blank_env(int fd, unsigned pagesize, unsigned itemsize)
{
    unsigned pagemask = pagesize - 1;
    unsigned count;

    count = pagesize - (itemsize & pagemask);

    if(write(fd, padding, count) != count) {
        return -1;
    } else {
        return 0;
    }
}

int main(int argc, char **argv)
{
    enviro_img_hdr hdr;

    char *dev_tree_fn = 0;
    void *dev_tree_data = 0;
    char *enviroment_fn = 0;
    void *enviroment_data = 0;
    unsigned env_size = 0;
    unsigned env_file_size = 0;
    char *splash_fn = 0;
    void *splash_data = 0;
    char *fb_img_fn = 0;
    void *fb_img_data = 0;
    char *charger_img_fn = 0;
    void *charger_img_data = 0;
    char *enviroimg = "enviroment.img";
    char *board = "unknown";
    unsigned pagesize = 2048;
    int fd;
    SHA_CTX ctx;
    uint8_t* sha;

    argc--;
    argv++;

    memset(&hdr, 0, sizeof(hdr));

    /* Need to figure out where to put each in memory */
    hdr.dev_tree_addr =  0x825f0000;
    hdr.splash_img_addr =  0xFFFFFFFF;
    hdr.fastboot_img_addr = 0xFFFFFFFF;
    hdr.charger_img_addr = 0xFFFFFFFF;
    hdr.enviroment_size = 0;

    while(argc > 0){
        char *arg = argv[0];
        char *val = argv[1];
        if (argc < 2) {
            return usage();
        }
        argc -= 2;
        argv += 2;

        if(!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
            enviroimg = val;
        } else if(!strcmp(arg, "--dev_tree")) {
            dev_tree_fn = val;
        } else if(!strcmp(arg, "--dt_base")) {
            unsigned base = strtoul(val, 0, 16);
            hdr.dev_tree_addr = base;
        } else if(!strcmp(arg, "--enviroment")) {
            enviroment_fn = val;
        } else if(!strcmp(arg, "--env_size")) {
            env_size = strtoul(val, 0, 16);
            hdr.enviroment_size = env_size;
        } else if(!strcmp(arg, "--splash_img")) {
            splash_fn = val;
        } else if(!strcmp(arg, "--fastboot_img")) {
            fb_img_fn = val;
        } else if(!strcmp(arg, "--charger_img")) {
            charger_img_fn = val;
        }  else if(!strcmp(arg, "--fb_addr")) {
            unsigned base = strtoul(val, 0, 16);
            hdr.splash_img_addr =  base;
            hdr.fastboot_img_addr = base;
            hdr.charger_img_addr = base;
        } else if(!strcmp(arg, "--board")) {
            board = val;
        } else if(!strcmp(arg, "--help") || !strcmp(arg, "-h")) {
            return usage();
	} else {
            return usage();
        }
    }
    hdr.page_size = pagesize;

    if (strlen(board) >= ENVIRO_NAME_SIZE) {
        fprintf(stderr,"error: board name too large\n");
        return usage();
    }

    strcpy(hdr.name, board);

    memcpy(hdr.magic, ENVIRO_MAGIC, ENVIRO_MAGIC_SIZE);
    if (dev_tree_fn == 0) {
        dev_tree_data = 0;
        hdr.dev_tree_size = 0;
	hdr.dev_tree_addr = 0xFFFFFFFF;
    } else {
        dev_tree_data = load_file(dev_tree_fn, &hdr.dev_tree_size);
        if(dev_tree_data == 0) {
            fprintf(stderr,"error: could not load device tree '%s'\n", dev_tree_fn);
            return 1;
        }
    }

    if (enviroment_fn == 0)
        enviroment_data = 0;
    else
         enviroment_data = load_file(enviroment_fn, &env_file_size);

    if(splash_fn == 0) {
        hdr.splash_img_addr = 0xFFFFFFFF;
        hdr.splash_img_size = 0x0;
    } else {
        splash_data = load_file(splash_fn, &hdr.splash_img_size);
        if(splash_data == 0) {
            fprintf(stderr,"error: could not load splash image '%s'\n", splash_fn);
            return 1;
        }
    }

    if (fb_img_fn == 0) {
        hdr.fastboot_img_addr = 0xFFFFFFFF;
        hdr.fastboot_img_size = 0x0;
    } else {
        fb_img_data = load_file(fb_img_fn, &hdr.fastboot_img_size);
        if(fb_img_data == 0) {
            fprintf(stderr,"error: could not load splash image '%s'\n", fb_img_fn);
            return 1;
        }
    }

    if (charger_img_fn == 0) {
        hdr.charger_img_addr = 0xFFFFFFFF;
        hdr.charger_img_size = 0x0;
    } else {
        charger_img_data = load_file(charger_img_fn, &hdr.charger_img_size);
        if(charger_img_data == 0) {
            fprintf(stderr,"error: could not load splash image '%s'\n", charger_img_fn);
            return 1;
        }
    }

    if (env_size) {
          hdr.enviroment_size = env_size + env_file_size;
         fprintf(stderr,"File size %d env_size %d total_size 0x%X\n", env_file_size, env_size, hdr.enviroment_size);
}
    /* put a hash of the contents in the header so boot images can be
     * differentiated based on their first 2k.
     */
    SHA_init(&ctx);
    SHA_update(&ctx, dev_tree_data, hdr.dev_tree_size);
    SHA_update(&ctx, &hdr.dev_tree_size, sizeof(hdr.dev_tree_size));
    if (enviroment_data)
        SHA_update(&ctx, enviroment_data, hdr.enviroment_size);
    SHA_update(&ctx, &hdr.enviroment_size, sizeof(hdr.enviroment_size));
    SHA_update(&ctx, splash_data, hdr.splash_img_size);
    SHA_update(&ctx, &hdr.splash_img_size, sizeof(hdr.splash_img_size));
    SHA_update(&ctx, fb_img_data, hdr.fastboot_img_size);
    SHA_update(&ctx, &hdr.fastboot_img_size, sizeof(hdr.fastboot_img_size));
    SHA_update(&ctx, charger_img_data, hdr.charger_img_size);
    SHA_update(&ctx, &hdr.charger_img_size, sizeof(hdr.charger_img_size));

    sha = SHA_final(&ctx);
    memcpy(hdr.id, sha,
           SHA_DIGEST_SIZE > sizeof(hdr.id) ? sizeof(hdr.id) : SHA_DIGEST_SIZE);

    fd = open(enviroimg, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        fprintf(stderr,"error: could not create '%s'\n", enviroimg);
        return 1;
    }

    if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) goto fail;
    if (write_padding(fd, pagesize, sizeof(hdr))) goto fail;

    if (dev_tree_data) {
        if(write(fd, dev_tree_data, hdr.dev_tree_size) != hdr.dev_tree_size) goto fail;
        if(write_padding(fd, pagesize, hdr.dev_tree_size)) goto fail;
    }

    if (hdr.enviroment_size) {
	if (enviroment_data) {
            if(write(fd, enviroment_data, hdr.enviroment_size) != hdr.enviroment_size) goto fail;
            if(write_padding(fd, pagesize, hdr.enviroment_size)) goto fail;
        } else {
            if(write_blank_env(fd, pagesize, hdr.enviroment_size)) goto fail;
        }
    }

    if (splash_data) {
        if(write(fd, splash_data, hdr.splash_img_size) != hdr.splash_img_size) goto fail;
        if(write_padding(fd, pagesize, hdr.splash_img_size)) goto fail;
    }

    if (fb_img_data) {
        if(write(fd, fb_img_data, hdr.fastboot_img_size) != hdr.fastboot_img_size) goto fail;
        if(write_padding(fd, pagesize, hdr.fastboot_img_size)) goto fail;
    }

    if (charger_img_data) {
        if (write(fd, charger_img_data, hdr.charger_img_size) != hdr.charger_img_size) goto fail;
        if (write_padding(fd, pagesize, hdr.charger_img_size)) goto fail;
    }

    return 0;

fail:
    unlink(enviroimg);
    close(fd);
    fprintf(stderr,"error: failed writing '%s': %s\n", enviroimg,
            strerror(errno));
    return 1;
}
