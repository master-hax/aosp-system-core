LOCAL_PATH:= $(call my-dir)

#######################################
# init.rc
# Only copy init.rc if the target doesn't have its own.
ifneq ($(TARGET_PROVIDES_INIT_RC),true)
include $(CLEAR_VARS)

LOCAL_MODULE := init.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_PREBUILT)
endif
#######################################
# init.environ.rc

include $(CLEAR_VARS)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE := init.environ.rc
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

# Put it here instead of in init.rc module definition,
# because init.rc is conditionally included.
#
# create some directories (some are mount points)
LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
    sbin dev proc sys system data)

include $(BUILD_SYSTEM)/base_rules.mk

# Give a chance to use an alternate init.environ.rc.in if
# TARGET_ENVIRON_RC_IN is set.
TARGET_ENVIRON_RC_IN ?= $(LOCAL_PATH)/init.environ.rc.in

$(LOCAL_BUILT_MODULE): $(TARGET_ENVIRON_RC_IN)
	@echo "Generate: $< -> $@"
	@mkdir -p $(dir $@)
	$(hide) sed -e 's?%BOOTCLASSPATH%?$(PRODUCT_BOOTCLASSPATH)?g' $< >$@

#######################################
