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

#include <utils/String8.h>

#include <iostream>

#include "fuzzer/FuzzedDataProvider.h"

#define MAX_BYTES 32

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    FuzzedDataProvider dataProvider(Data, Size);

    // Generate vector lengths
    const size_t kVecOneLen = dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES);
    const size_t kVecTwoLen = dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_BYTES);

    // Populate vectors
    std::vector<char> vec = dataProvider.ConsumeBytesWithTerminator<char>(kVecOneLen);
    std::vector<char> vec_two = dataProvider.ConsumeBytesWithTerminator<char>(kVecTwoLen);

    // Get data pointers
    char* str = vec.data();
    char* str_two = vec_two.data();

    // Create UTF-8 pointers
    android::String8 str_one_utf8 = android::String8(str);
    android::String8 str_two_utf8 = android::String8(str_two);
    android::String8 str_one_appended_utf8 = android::String8(str);

    // Append and format operations
    str_one_appended_utf8.append(str_two_utf8);
    str_one_appended_utf8.appendFormat(str, str_two);
    str_one_appended_utf8 = str_one_appended_utf8.format(str, str_two);
    // Find operation
    int start_index = dataProvider.ConsumeIntegralInRange<int>(0, str_one_utf8.size());
    str_one_appended_utf8.find(str, start_index);
    // Bytes and size
    str_one_appended_utf8.bytes();
    str_one_appended_utf8.isEmpty();
    str_one_appended_utf8.length();
    // For some reason String8 contains path manipulation logic
    str_one_appended_utf8.setPathName(dataProvider.ConsumeBytesWithTerminator<char>(5).data());
    str_one_appended_utf8.appendPath(dataProvider.ConsumeBytesWithTerminator<char>(5).data());
    str_one_appended_utf8.getBasePath();
    str_one_appended_utf8.getPathExtension();
    str_one_appended_utf8.getPathLeaf();
    str_one_appended_utf8.getPathDir();
    android::String8 path_out_str = android::String8();
    str_one_appended_utf8.walkPath(&path_out_str);
    str_one_appended_utf8.convertToResPath();

    // Upper/lower checks. Unlike String16, String8 supports conversion to both
    // upper and lower case.
    str_one_appended_utf8.toUpper();
    str_one_appended_utf8.toLower();

    str_one_appended_utf8.size();
    str_one_appended_utf8.removeAll(str_two);
    str_one_appended_utf8.compare(str_one_utf8);
    str_one_appended_utf8.compare(str_two_utf8);

    // Just to be extra sure these can be freed, we're going to explicitly clear
    // them
    str_one_utf8.clear();
    str_two_utf8.clear();
    path_out_str.clear();
    str_one_appended_utf8.clear();
    return 0;
}
