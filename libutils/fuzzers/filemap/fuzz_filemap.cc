/*
 * Copyright 2020 The Android Open Source Project
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

#include <iostream>

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/FileMap.h"

#define MAX_STR_SIZE 256
#define MAX_FILENAME_SIZE 32

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    FuzzedDataProvider dataProvider(Data, Size);
    FILE* fp = tmpfile();
    // Generate file contents
    std::string contents = dataProvider.ConsumeRandomLengthString(MAX_STR_SIZE);
    // Make sure there's something there.
    if (contents.length() > 0) {
        const char* bytes = contents.c_str();
        fputs(bytes, fp);
        rewind(fp);
    }
    int fd = fileno(fp);

    android::FileMap m;

    // Generate create() params
    std::string orig_name = dataProvider.ConsumeRandomLengthString(MAX_FILENAME_SIZE);
    bool should_free_orig_name = false;
    if (orig_name.length() == 0) {
        orig_name = std::string("abc_test_file.txt");
        should_free_orig_name = true;
    }
    size_t length = dataProvider.ConsumeIntegralInRange<size_t>(1, SIZE_MAX);
    off64_t offset = dataProvider.ConsumeIntegralInRange<off64_t>(1, INT64_MAX);
    bool read_only = dataProvider.ConsumeBool();
    m.create(orig_name.c_str(), fd, offset, length, read_only);

    m.getDataOffset();
    m.getFileName();
    m.getDataLength();
    m.getDataPtr();
    uint8_t enum_idx = dataProvider.ConsumeIntegralInRange<uint8_t>(0, 4);
    m.advise(static_cast<android::FileMap::MapAdvice>(enum_idx));
    fclose(fp);
    return 0;
}
