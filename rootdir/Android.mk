LOCAL_PATH:= $(call my-dir)

#######################################
# init.rc
include $(CLEAR_VARS)

LOCAL_MODULE := init.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_PREBUILT)

#######################################
# init-debug.rc
include $(CLEAR_VARS)

LOCAL_MODULE := init-debug.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/init

include $(BUILD_PREBUILT)

#######################################
# asan.options
ifneq ($(filter address,$(SANITIZE_TARGET)),)

include $(CLEAR_VARS)

LOCAL_MODULE := asan.options
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(TARGET_OUT)

include $(BUILD_PREBUILT)

# ASAN extration.
ASAN_EXTRACT_FILES :=
ifeq ($(SANITIZE_TARGET_SYSTEM),true)
include $(CLEAR_VARS)
LOCAL_MODULE:= asan_extract
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := asan_extract.sh
LOCAL_INIT_RC := asan_extract.rc
# We need bzip2 on device for extraction.
LOCAL_REQUIRED_MODULES := bzip2
include $(BUILD_PREBUILT)
ASAN_EXTRACT_FILES := asan_extract
endif

endif

#######################################
# init.environ.rc

include $(CLEAR_VARS)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE := init.environ.rc
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

EXPORT_GLOBAL_ASAN_OPTIONS :=
ifneq ($(filter address,$(SANITIZE_TARGET)),)
  EXPORT_GLOBAL_ASAN_OPTIONS := export ASAN_OPTIONS include=/system/asan.options
  LOCAL_REQUIRED_MODULES := asan.options $(ASAN_OPTIONS_FILES) $(ASAN_EXTRACT_FILES)
endif

EXPORT_GLOBAL_GCOV_OPTIONS :=
ifeq ($(NATIVE_COVERAGE),true)
  EXPORT_GLOBAL_GCOV_OPTIONS := export GCOV_PREFIX /data/misc/gcov
endif

include $(BUILD_SYSTEM)/base_rules.mk

# Regenerate init.environ.rc if PRODUCT_BOOTCLASSPATH has changed.
bcp_md5 := $(word 1, $(shell echo $(PRODUCT_BOOTCLASSPATH) $(PRODUCT_SYSTEM_SERVER_CLASSPATH) | $(MD5SUM)))
bcp_dep := $(intermediates)/$(bcp_md5).bcp.dep
$(bcp_dep) :
	$(hide) mkdir -p $(dir $@) && rm -rf $(dir $@)*.bcp.dep && touch $@

$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/init.environ.rc.in $(bcp_dep)
	@echo "Generate: $< -> $@"
	@mkdir -p $(dir $@)
	$(hide) sed -e 's?%BOOTCLASSPATH%?$(PRODUCT_BOOTCLASSPATH)?g' $< >$@
	$(hide) sed -i -e 's?%SYSTEMSERVERCLASSPATH%?$(PRODUCT_SYSTEM_SERVER_CLASSPATH)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_ASAN_OPTIONS%?$(EXPORT_GLOBAL_ASAN_OPTIONS)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_GCOV_OPTIONS%?$(EXPORT_GLOBAL_GCOV_OPTIONS)?g' $@

bcp_md5 :=
bcp_dep :=

# Append PLATFORM_VNDK_VERSION to base name.
define append_vndk_version
$(strip \
  $(basename $(1)).$(PLATFORM_VNDK_VERSION)$(suffix $(1)) \
)
endef


#######################################
# ld.config.txt selection variables
#
_enforce_vndk_at_runtime := false
ifdef BOARD_VNDK_VERSION
  ifneq ($(BOARD_VNDK_RUNTIME_DISABLE),true)
    _enforce_vndk_at_runtime := true
  endif
endif

_enforce_vndk_lite_at_runtime := false
ifeq ($(_enforce_vndk_at_runtime),false)
  ifeq ($(PRODUCT_TREBLE_LINKER_NAMESPACES)|$(SANITIZE_TARGET),true|)
    _enforce_vndk_lite_at_runtime := true
  endif
endif

#######################################
# ld.config.txt
#
# For VNDK enforced devices that have defined BOARD_VNDK_VERSION, use
# "ld.config.txt" as a source file. This configuration includes strict VNDK
# run-time restrictions for vendor process.
#
# Other treblized devices, that have not defined BOARD_VNDK_VERSION or that
# have set BOARD_VNDK_RUNTIME_DISABLE to true, use "ld.config.vndk_lite.txt"
# as a source file. This configuration does not have strict VNDK run-time
# restrictions.
#
# If the device is not treblized, use "ld.config.legacy.txt" for legacy
# namespace configuration.
#
include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)

ifeq ($(_enforce_vndk_at_runtime),true)

# for VNDK enforced devices
LOCAL_MODULE_STEM := $(call append_vndk_version,$(LOCAL_MODULE))
include $(BUILD_SYSTEM)/base_rules.mk
ld_config_template := $(LOCAL_PATH)/etc/ld.config.txt
check_backward_compatibility := true
vndk_version := $(PLATFORM_VNDK_VERSION)
include $(LOCAL_PATH)/update_and_install_ld_config.mk

else ifeq ($(_enforce_vndk_lite_at_runtime),true)

# for treblized but VNDK lightly enforced devices
LOCAL_MODULE_STEM := ld.config.vndk_lite.txt
include $(BUILD_SYSTEM)/base_rules.mk
ld_config_template := $(LOCAL_PATH)/etc/ld.config.vndk_lite.txt
vndk_version := $(PLATFORM_VNDK_VERSION)
libz_is_llndk := true
include $(LOCAL_PATH)/update_and_install_ld_config.mk

else

# for legacy non-treblized devices
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
LOCAL_SRC_FILES := etc/ld.config.legacy.txt
include $(BUILD_PREBUILT)

endif  # ifeq ($(_enforce_vndk_at_runtime),true)

# ld.config.txt for VNDK versions older than PLATFORM_VNDK_VERSION
# are built with the VNDK libraries lists under /prebuilts/vndk.
#
# ld.config.$(VER).txt is built and installed for all VNDK versions
# listed in PRODUCT_EXTRA_VNDK_VERSIONS.
#
# $(1): VNDK version
define build_versioned_ld_config
include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.$(1).txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $$(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
ld_config_template := $(LOCAL_PATH)/etc/ld.config.txt
check_backward_compatibility := true
vndk_version := $(1)
lib_list_from_prebuilts := true
include $(LOCAL_PATH)/update_and_install_ld_config.mk
endef

# For VNDK snapshot versions prior to 28, ld.config.txt is installed from the
# prebuilt under /prebuilts/vndk
vndk_snapshots := $(wildcard prebuilts/vndk/*)
supported_vndk_snapshot_versions := \
  $(strip $(foreach ver,$(patsubst prebuilts/vndk/v%,%,$(vndk_snapshots)),\
    $(if $(call math_gt_or_eq,$(ver),28),$(ver),)))
$(eval $(foreach ver,$(supported_vndk_snapshot_versions),\
  $(call build_versioned_ld_config,$(ver))))

vndk_snapshots :=
supported_vndk_snapshot_versions :=

#######################################
# ld.config.vndk_lite.txt
#
# This module is only for GSI.
#
ifeq ($(_enforce_vndk_lite_at_runtime),false)

include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.vndk_lite.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
ld_config_template := $(LOCAL_PATH)/etc/ld.config.vndk_lite.txt
vndk_version := $(PLATFORM_VNDK_VERSION)
libz_is_llndk := true
include $(LOCAL_PATH)/update_and_install_ld_config.mk

endif  # ifeq ($(_enforce_vndk_lite_at_runtime),false)

_enforce_vndk_at_runtime :=
_enforce_vndk_lite_at_runtime :=

#######################################
# ld.config.txt for recovery
include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.recovery.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := etc/ld.config.recovery.txt
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/etc
LOCAL_MODULE_STEM := ld.config.txt
include $(BUILD_PREBUILT)

#######################################
# llndk.libraries.txt
include $(CLEAR_VARS)
LOCAL_MODULE := llndk.libraries.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(call append_vndk_version,$(LOCAL_MODULE))
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE): PRIVATE_LLNDK_LIBRARIES := $(LLNDK_LIBRARIES)
$(LOCAL_BUILT_MODULE):
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo -n > $@
	$(hide) $(foreach lib,$(PRIVATE_LLNDK_LIBRARIES), \
		echo $(lib).so >> $@;)

#######################################
# vndksp.libraries.txt
include $(CLEAR_VARS)
LOCAL_MODULE := vndksp.libraries.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(call append_vndk_version,$(LOCAL_MODULE))
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_SAMEPROCESS_LIBRARIES := $(VNDK_SAMEPROCESS_LIBRARIES)
$(LOCAL_BUILT_MODULE):
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo -n > $@
	$(hide) $(foreach lib,$(PRIVATE_VNDK_SAMEPROCESS_LIBRARIES), \
		echo $(lib).so >> $@;)
