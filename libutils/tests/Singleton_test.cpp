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

#include <dlfcn.h>

#include <utils/Singleton.h>

#include <gtest/gtest.h>

#include "Singleton_test.h"

namespace android {

class SingletonTest : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(SingletonTest, CrossLibrary) {
    // libutils_tests_singleton1.so contains the ANDROID_SINGLETON_STATIC_INSTANCE
    // definition of SingletonTestData, load it first.
    void* handle1 = dlopen("libutils_tests_singleton1.so", RTLD_NOW);
    ASSERT_NE(handle1, nullptr) << dlerror();

    // libutils_tests_singleton2.so references SingletonTestData but should not
    // have a definition
    void* handle2 = dlopen("libutils_tests_singleton2.so", RTLD_NOW);
    ASSERT_NE(handle2, nullptr) << dlerror();

    using has = typeof(singletonHasInstance);
    using get = typeof(singletonGetInstanceContents);
    using set = typeof(singletonSetInstanceContents);

    has* has1 = reinterpret_cast<has*>(dlsym(handle1, "singletonHasInstance"));
    ASSERT_NE(nullptr, has1) << dlerror();
    has* has2 = reinterpret_cast<has*>(dlsym(handle2, "singletonHasInstance"));
    ASSERT_NE(nullptr, has2) << dlerror();
    get* get1 = reinterpret_cast<get*>(dlsym(handle1, "singletonGetInstanceContents"));
    ASSERT_NE(nullptr, get1) << dlerror();
    get* get2 = reinterpret_cast<get*>(dlsym(handle2, "singletonGetInstanceContents"));
    ASSERT_NE(nullptr, get2) << dlerror();
    set* set1 = reinterpret_cast<set*>(dlsym(handle2, "singletonSetInstanceContents"));
    ASSERT_NE(nullptr, set1) << dlerror();

    EXPECT_FALSE(has1());
    EXPECT_FALSE(has2());
    set1(12345678);
    EXPECT_TRUE(has1());
    EXPECT_TRUE(has2());
    EXPECT_EQ(12345678U, get1());
    EXPECT_EQ(12345678U, get2());
}

}
