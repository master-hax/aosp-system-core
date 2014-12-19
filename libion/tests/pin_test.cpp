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

#include <sys/mman.h>

#include <gtest/gtest.h>

#include <ion/ion.h>
#include <vector>
#include "ion_test_fixture.h"
#include "ion_test_fixture.h"

using namespace std;
class PinUnpin : public IonAllHeapsTest {
};

TEST_F(PinUnpin, PinUnpin)
{
    for (unsigned int heapMask : m_allHeaps) {
        ion_user_handle_t handle = 0;
       ASSERT_EQ(0, ion_alloc(m_ionFd, 4096, 0, heapMask, 0, &handle));
        ASSERT_EQ(0, ion_unpin(m_ionFd, handle));
        ASSERT_EQ(0, ion_pin(m_ionFd, handle));
        ASSERT_EQ(0, ion_free(m_ionFd, handle));
    }
}

TEST_F(PinUnpin, FreeUnpinnedThenPinned)
{
    for (unsigned int heapMask : m_allHeaps) {
        ion_user_handle_t handle = 0;
        ASSERT_EQ(0, ion_alloc(m_ionFd, 4096, 0, heapMask, 0, &handle));
        ASSERT_EQ(0, ion_unpin(m_ionFd, handle));
        ASSERT_EQ(-EINVAL, ion_free(m_ionFd, handle));
        ASSERT_EQ(0, ion_pin(m_ionFd, handle));
        ASSERT_EQ(0, ion_free(m_ionFd, handle));
        ASSERT_EQ(-EINVAL, ion_pin(m_ionFd, handle));
    }
}

TEST_F(PinUnpin, InvalidHandle)
{
    for (unsigned int heapMask : m_allHeaps) {
        ion_user_handle_t handle = 0;
        ASSERT_EQ(0, ion_alloc(m_ionFd, 4096, 0, heapMask, 0, &handle));
        ASSERT_EQ(0, ion_free(m_ionFd, handle));
        ASSERT_EQ(-EINVAL, ion_unpin(m_ionFd, handle));
    }
}

TEST_F(PinUnpin, Allocate) {
    unsigned int heap = m_allHeaps[0];
    vector<ion_user_handle_t> handles;

    ion_user_handle_t handle = 0;
    unsigned cur_alloc = 0;
    int result;
    while((result = ion_alloc(m_ionFd, 1024*1024, 0, heap, 0, &handle)) == 0) {
        handles.push_back(handle);
    }

    // we shoiuld have run out of memory
    ASSERT_EQ(-ENOMEM, result);

    for (int i = 0; i < 10; i++) {
        ion_unpin(m_ionFd, handles[i]);
    }

    for (int i = 0; i < 10; i++) {
        ASSERT_EQ(0, ion_alloc(m_ionFd, 1024*1024, 0, heap, 0, &handle));
    }

    for (int i = 0; i < 10; i++) {
        cout << ion_pin(m_ionFd, handles[i]) << endl;
    }

}
