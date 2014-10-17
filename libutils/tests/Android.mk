#
# Copyright (C) 2014 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := BasicHashtable_test.cpp
LOCAL_MODULE := BasicHashtable_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := BlobCache_test.cpp
LOCAL_MODULE := BlobCache_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := BitSet_test.cpp
LOCAL_MODULE := BitSet_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := Looper_test.cpp
LOCAL_MODULE := Looper_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := LruCache_test.cpp
LOCAL_MODULE := LruCache_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := String8_test.cpp
LOCAL_MODULE := String8_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := Unicode_test.cpp
LOCAL_MODULE := Unicode_test
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SHARED_LIBRARIES := libutils
LOCAL_SRC_FILES := Vector_test.cpp
LOCAL_MODULE := Vector_test
include $(BUILD_NATIVE_TEST)
