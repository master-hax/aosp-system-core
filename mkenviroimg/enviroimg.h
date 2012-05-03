/* tools/mkenviroimg/enviromimg.h
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

#ifndef _ENVIRO_IMAGE_H_
#define _ENVIRO_IMAGE_H_

typedef struct enviro_img_hdr enviro_img_hdr;

#define ENVIRO_MAGIC "ANDROID_ENV!"
#define ENVIRO_MAGIC_SIZE 12
#define ENVIRO_NAME_SIZE 16
#define ENVIRO_ARGS_SIZE 512

struct enviro_img_hdr
{
    unsigned char magic[ENVIRO_MAGIC_SIZE];

    unsigned dev_tree_size;  /* size in bytes */
    unsigned dev_tree_addr;  /* physical load addr */

    unsigned enviroment_size; /* size in bytes */

    unsigned splash_img_size;  /* size in bytes */
    unsigned splash_img_addr;  /* physical load addr */

    unsigned fastboot_img_size;  /* size in bytes */
    unsigned fastboot_img_addr;  /* physical load addr */

    unsigned charger_img_size;  /* size in bytes */
    unsigned charger_img_addr;  /* physical load addr */

    unsigned page_size;    /* flash page size we assume */

    unsigned char name[ENVIRO_NAME_SIZE]; /* asciiz product name */

    unsigned id[8]; /* timestamp / checksum / sha1 / etc */
};

/*
** +-----------------+
** | enviroment hdr  | 1 page
** +-----------------+
** | boot splash     | o pages
** +-----------------+
** | fastboot splash | p pages
** +-----------------+
** | charger splash  | r pages
** +-----------------+
** | enviroment      | m pages
** +-----------------+
** | device tree     | n pages
** +-----------------+
**
** n = (dev_tree_size + page_size - 1) / page_size
** m = (enviroment_size + page_size - 1) / page_size
** o = (splash_img_size + page_size - 1) / page_size
** p = (fastboot_img_size + page_size - 1) / page_size
** r = (charger_img_size + page_size - 1) / page_size
**
** Everything here is optional not manadatory
*/

#endif
