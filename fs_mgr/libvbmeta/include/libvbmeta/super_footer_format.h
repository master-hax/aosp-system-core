/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef SUPER_FOOTER_FORMAT_H_
#define SUPER_FOOTER_FORMAT_H_

#ifdef __cplusplus
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic signature for SuperAVBFooter. */
#define SUPER_FOOTER_MAGIC 0x666F7472

/* Current metadata version. */
#define SUPER_FOOTER_MAJOR_VERSION 1
#define SUPER_FOOTER_MINOR_VERSION 0

#define SUPER_FOOTER_SIZE 64

struct SuperFooter {
  uint32_t magic;
  uint16_t major_version;
  uint16_t minor_version;
  uint64_t avbfooter_offset;
  uint8_t reserved[48];
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SUPER_FOOTER_FORMAT_H_ */