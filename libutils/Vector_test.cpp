/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "Vector_test"

#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <unistd.h>

#include <android/log.h>
#include <gtest/gtest.h>
#include <utils/Vector.h>

using android::Vector;

TEST(VectorTest, CopyOnWrite_CopyAndAddElements) {
    Vector<int> vector;
    Vector<int> other;
    vector.setCapacity(8);

    vector.add(1);
    vector.add(2);
    vector.add(3);

    EXPECT_EQ(3U, vector.size());

    // copy the vector
    other = vector;

    EXPECT_EQ(3U, other.size());

    // add an element to the first vector
    vector.add(4);

    // make sure the sizes are correct
    EXPECT_EQ(4U, vector.size());
    EXPECT_EQ(3U, other.size());

    // add an element to the copy
    other.add(5);

    // make sure the sizes are correct
    EXPECT_EQ(4U, vector.size());
    EXPECT_EQ(4U, other.size());

    // make sure the content of both vectors are correct
    EXPECT_EQ(vector[3], 4);
    EXPECT_EQ(other[3], 5);
}

TEST(VectorTest, SetCapacity_Overflow) {
    Vector<int> v;
    EXPECT_DEATH(v.setCapacity(SIZE_MAX / sizeof(int) + 1), "Assertion failed");
}

TEST(VectorTest, SetCapacity_ShrinkBelowSize) {
    Vector<int> v;
    v.add(1);
    v.add(2);
    v.add(3);
    v.add(4);

    v.setCapacity(8);
    ASSERT_EQ(8U, v.capacity());
    v.setCapacity(2);
    ASSERT_EQ(8U, v.capacity());
}

TEST(VectorTest, _grow_OverflowSize) {
    Vector<int> v;
    v.add(1);

    // Checks that the size calculation (not the capacity calculation) doesn't
    // overflow : the size here will be (1 + SIZE_MAX).
    EXPECT_DEATH(v.insertArrayAt(nullptr, 0, SIZE_MAX), "new_size overflow");
}

TEST(VectorTest, _grow_OverflowCapacityDoubling) {
    Vector<int> v;

    // This should fail because the calculated capacity will overflow even though
    // the size of the vector doesn't.
    EXPECT_DEATH(v.insertArrayAt(nullptr, 0, (SIZE_MAX - 1)), "new_capacity overflow");
}

TEST(VectorTest, _grow_OverflowBufferAlloc) {
    Vector<int> v;
    // This should fail because the capacity * sizeof(int) overflows, even
    // though the capacity itself doesn't.
    EXPECT_DEATH(v.insertArrayAt(nullptr, 0, (SIZE_MAX / 2)), "new_alloc_size overflow");
}

TEST(VectorTest, editArray_Shared) {
    Vector<int> vector1;
    vector1.add(1);
    vector1.add(2);
    vector1.add(3);
    vector1.add(4);

    Vector<int> vector2 = vector1;
    ASSERT_EQ(vector1.array(), vector2.array());
    // We must make a copy here, since we're not the exclusive owners
    // of this array.
    ASSERT_NE(vector1.editArray(), vector2.editArray());

    // Vector doesn't implement operator ==.
    ASSERT_EQ(vector1.size(), vector2.size());
    for (size_t i = 0; i < vector1.size(); ++i) {
        EXPECT_EQ(vector1[i], vector2[i]);
    }
}

TEST(VectorTest, removeItemsAt_front) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);

    v.removeItemsAt(0, 0);
    ASSERT_EQ(666U, v.size());
    ASSERT_EQ(0, v[0]);

    v.removeItemsAt(0, 2);
    ASSERT_EQ(664U, v.size());
    ASSERT_EQ(2, v[0]);
}

TEST(VectorTest, removeItemsAt_mid) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);

    v.removeItemsAt(100, 0);
    ASSERT_EQ(666U, v.size());
    ASSERT_EQ(100, v[100]);

    v.removeItemsAt(100, 100);
    ASSERT_EQ(99, v[99]);
    ASSERT_EQ(200, v[100]);
}

TEST(VectorTest, removeItemsAt_back) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);

    v.removeItemsAt(v.size(), 0);
    ASSERT_EQ(666U, v.size());
    ASSERT_EQ(665, v[665]);

    v.removeItemsAt(v.size() - 2, 2);
    ASSERT_EQ(664U, v.size());
    ASSERT_EQ(664, v[664]);
}

TEST(VectorTest, removeItemsAt_too_many) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);

    ASSERT_EQ(666, v.removeItemsAt(666, 0));
    ASSERT_EQ(android::BAD_INDEX, v.removeItemsAt(667, 0));
    ASSERT_EQ(android::BAD_INDEX, v.removeItemsAt(666, SIZE_MAX));
    ASSERT_EQ(android::BAD_INDEX, v.removeItemsAt(SIZE_MAX, SIZE_MAX));
}

TEST(VectorTest, replaceAt) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);

    ASSERT_EQ(0, v.itemAt(0));
    ASSERT_EQ(0, v.replaceAt(123, 0));
    ASSERT_EQ(123, v.itemAt(0));

    ASSERT_EQ(665, v.itemAt(v.size() - 1));
    ASSERT_EQ(static_cast<ssize_t>(v.size() - 1), v.replaceAt(123, v.size() - 1));
    ASSERT_EQ(123, v.itemAt(v.size() - 1));
}

TEST(VectorTest, replaceAt_too_high) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);
    ASSERT_EQ(android::BAD_INDEX, v.replaceAt(v.size()));
    ASSERT_EQ(android::BAD_INDEX, v.replaceAt(SIZE_MAX));
}

TEST(VectorTest, insertAt) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);

    ASSERT_EQ(0, v.itemAt(0));
    ASSERT_EQ(0, v.insertAt(-1, 0));
    ASSERT_EQ(-1, v.itemAt(0));
    ASSERT_EQ(0, v.itemAt(1));

    ASSERT_EQ(0, v.itemAt(v.size()));
    ASSERT_EQ(667, v.insertAt(666, v.size()));
    ASSERT_EQ(666, v.itemAt(v.size() - 1));
    ASSERT_EQ(0, v.itemAt(v.size()));
}

TEST(VectorTest, insertAt_too_high) {
    Vector<int> v;
    for (int i = 0; i < 666; i++) v.add(i);
    ASSERT_EQ(android::BAD_INDEX, v.insertAt(v.size() + 1));
    ASSERT_EQ(android::BAD_INDEX, v.insertAt(SIZE_MAX));
}
