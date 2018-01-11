# Copyright 2017 The Android Open Source Project
#
#
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_STATIC_JAVA_LIBRARIES := builder fastdeployguava
LOCAL_SRC_FILES := $(call all-java-files-under,deployagent) $(call all-java-files-under,deploylib) $(call all-proto-files-under, proto)
LOCAL_PROTOC_FLAGS := --proto_path=$(LOCAL_PATH)
LOCAL_MODULE := fastdeploy
LOCAL_MODULE_STEM := deployagent
LOCAL_MIN_SDK_VERSION := 24
include $(BUILD_JAVA_LIBRARY)

include $(CLEAR_VARS)
LOCAL_PREBUILT_STATIC_JAVA_LIBRARIES := builder:prebuilt/builder-3.0.1.jar fastdeployguava:prebuilt/guava-22.0.jar
include $(BUILD_MULTI_PREBUILT) 

include $(CLEAR_VARS)
LOCAL_STATIC_JAVA_LIBRARIES := builder_host fastdeployguava_host
LOCAL_SRC_FILES := $(call all-java-files-under, deploypatchgenerator) $(call all-java-files-under, deploylib) $(call all-proto-files-under, proto)
LOCAL_PROTOC_FLAGS := --proto_path=$(LOCAL_PATH)
LOCAL_MODULE := fastdeploy
LOCAL_MODULE_STEM := deploypatchgenerator
LOCAL_JAR_MANIFEST := deploypatchgenerator/manifest.txt
include $(BUILD_HOST_JAVA_LIBRARY)

include $(CLEAR_VARS)
LOCAL_IS_HOST_MODULE := true
LOCAL_PREBUILT_STATIC_JAVA_LIBRARIES := builder_host:prebuilt/builder-3.0.1.jar fastdeployguava_host:prebuilt/guava-22.0.jar
#include $(BUILD_MULTI_PREBUILT) 
include $(BUILD_HOST_PREBUILT)

