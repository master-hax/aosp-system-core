# Copyright 2008 The Android Open Source Project
#
LOCAL_PATH := $(call my-dir)

# Determine whether to build mincrypt from system/core or from system/mincrypt.
# The mincrypt source is temporarily present in both locations during the
# process of moving mincrypt to system/mincrypt.
# TODO(mnissler): Remove this after the transition is complete.
ifndef MINCRYPT_STANDALONE
MINCRYPT_STANDALONE := false
endif

ifeq ($(MINCRYPT_STANDALONE),false)
$(warning Building system/core mincrypt)

include $(CLEAR_VARS)
LOCAL_MODULE := libmincrypt
LOCAL_SRC_FILES := dsa_sig.c p256.c p256_ec.c p256_ecdsa.c rsa.c sha.c sha256.c
LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libmincrypt
LOCAL_SRC_FILES := dsa_sig.c p256.c p256_ec.c p256_ecdsa.c rsa.c sha.c sha256.c
LOCAL_CFLAGS := -Wall -Werror
include $(BUILD_HOST_STATIC_LIBRARY)

include $(LOCAL_PATH)/tools/Android.mk \
        $(LOCAL_PATH)/test/Android.mk

endif  # MINCRYPT_STANDALONE == false
