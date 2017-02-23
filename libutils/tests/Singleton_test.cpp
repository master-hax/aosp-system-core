/*
 * Copyright (C) 2010 The Android Open Source Project
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

#define LOG_TAG "Singleton_test"
#include <utils/Singleton.h>

#include <gtest/gtest.h>

#include "Singleton_test.h"

namespace android {

// Singleton<SingletonTestStruct> is referenced here and in Singleton_test2.cpp,
// but only defined here.
ANDROID_SINGLETON_STATIC_INSTANCE(SingletonTestData);

class SingletonTest : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(SingletonTest, CrossLibrary) {
    EXPECT_FALSE(SingletonTestData::hasInstance());
    EXPECT_FALSE(singletonHasInstance());
    SingletonTestData::getInstance().contents = 0xdeadbeef;
    EXPECT_TRUE(SingletonTestData::hasInstance());
    EXPECT_TRUE(singletonHasInstance());
    EXPECT_EQ(singletonGetInstanceContents(), 0xdeadbeef);
}

}
