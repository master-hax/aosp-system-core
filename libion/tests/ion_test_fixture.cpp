/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <ion/ion.h>

#include "ion_test_fixture.h"

IonTest::IonTest() : ionfd(-1), ion_heaps() {}

void IonTest::SetUp() {
    ionfd = ion_open();
    ASSERT_GE(ionfd, 0);

    int heap_count;
    int ret = ion_query_heap_cnt(ionfd, &heap_count);
    ASSERT_EQ(ret, 0);
    ASSERT_GT(heap_count, 0);

    ion_heaps.resize(heap_count, {});
    ret = ion_query_get_heaps(ionfd, heap_count, ion_heaps.data());
    ASSERT_EQ(ret, 0);

    // TODO: find a better way to dump the heap information at the begging of the
    // test only once. This SetUp() is called per test case and pollutes the logs
#if 0
    for (auto& heap : ion_heaps) {
        GTEST_LOG_(INFO) << "heap: " << heap.name << ": 0x" << std::hex << heap.type << ": "
                         << heap.heap_id;
    }
#endif
}

void IonTest::TearDown() {
    ion_close(ionfd);
}
