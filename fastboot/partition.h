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

#ifndef PARTITION_H_
#define PARTITION_H_

#define FB_PARTITION_MAGIC  0x54504246 //"FBPT" (FastBoot Partition Table)

#define GPT_ATTR_SYSTEM     1
#define GPT_ATTR_BOOTABLE   (1ULL << 2)
#define GPT_ATTR_RO         (1ULL << 60)
#define GPT_ATTR_HIDDEN     (1ULL << 62)

#define PT_TYPE_GPT         1

struct partition_entry {
    uint64_t size;
    uint64_t attr;
    uint32_t extend;
    char name[36];
    char type[38];
    char guid[38];
} __attribute__((__packed__));

struct partition_table {
    uint32_t magic;
    uint32_t lun;
    uint32_t type;
    uint32_t num;
    char disk_guid[40];
    struct partition_entry pe[];
} __attribute__((__packed__));

struct partition_table **get_partition_table(std::string fname);
void free_partition_table(struct partition_table **pt);

#endif /* PARTITION_H_ */
