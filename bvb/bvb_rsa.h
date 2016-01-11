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

/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _BVB_RSA_H_
#define _BVB_RSA_H_

#include "bvb_sysdeps.h"

#define BVB_RSA2048_NUM_BYTES 256
#define BVB_RSA4096_NUM_BYTES 512
#define BVB_RSA8192_NUM_BYTES 1024

/* Using the key given by |key_header|, verify a RSA signature |sig|
 * of length |sig_num_bytes| against an expected |hash| of length
 * |hash_num_bytes|. The padding to expect must be passed in using
 * |padding| of length |padding_num_bytes|.
 *
 * The data in |key| must match the format defined in
 * |BvbRSAPublicKeyHeader|, including the two large numbers
 * following. The |key_num_bytes| must be the size of the entire
 * serialized key.
 *
 * Returns 0 if verification fails, non-zero otherwise.
 */
int bvb_RSAVerify(const uint8_t* key, size_t key_num_bytes,
                  const uint8_t* sig, size_t sig_num_bytes,
                  const uint8_t* hash, size_t hash_num_bytes,
                  const uint8_t* padding, size_t padding_num_bytes);

#endif  /* _BVB_RSA_H_ */
