/*
 * Copyright (C) 2019 The Android Open Source Project
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

/* This .h file is intended for CPP clients (usually fastbootd and update_engine)  */

#pragma once

#include <string>
#include <vector>

#include "vbmeta_table_format_c.h"

struct InternalVBMetaDescriptor : VBMetaDescriptor {
    /*  64: The partition's name */
    std::string partition_name;
};

struct VBMetaTable {
    VBMetaTableHeader header;
    std::vector<InternalVBMetaDescriptor> descriptors;
};

// Light version of InternalVBMetaDescriptor for returning value.
struct VBMetaInfo {
    uint64_t vbmeta_offset;
    uint32_t vbmeta_size;
    std::string partition_name;
};