
/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef CRYPTO_UTILS_BYTE_ORDER_H
#define CRYPTO_UTILS_BYTE_ORDER_H

#include <sys/param.h>  // for BYTE_ORDER

static inline uint32_t crypto_utils_bswap32(uint32_t v)  {
  return (v << 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) |
         (v >> 24);
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define crypto_utils_le32toh(x) (x)
#define crypto_utils_htole32(x) (x)
#define crypto_utils_be32toh(x) crypto_utils_bswap32(x)
#define crypto_utils_htobe32(x) crypto_utils_bswap32(x)
#elif BYTE_ORDER == BIG_ENDIAN
#define crypto_utils_le32toh(x) crypto_utils_bswap32(x)
#define crypto_utils_htole32(x) crypto_utils_bswap32(x)
#define crypto_utils_be32toh(x) (x)
#define crypto_utils_htobe32(x) (x)
#else
#error BYTE_ORDER definition missing!
#endif

#endif  // CRYPTO_UTILS_BYTE_ORDER_H
