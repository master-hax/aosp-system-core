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
#pragma once

/* Use this header file for getting access to the internals of libsparse
 * This is useful for testing and creating malformed sparse images
 */
#include "../../backed_block.h"
#include "../../output_file.h"
#include "../../sparse_crc32.h"
#include "../../sparse_defs.h"
#include "../../sparse_file.h"
#include "../../sparse_format.h"
#include "sparse.h"
