LOCAL_PATH:= $(call my-dir)

# init.environ.rc
# TODO(b/353429422): move LOCAL_POST_INSTALL_CMD to other rules and remove Android.mk module.

include $(CLEAR_VARS)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE := init.environ.rc
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

# Put it here instead of in init.rc module definition,
# because init.rc is conditionally included.
#
# create some directories (some are mount points) and symlinks
LOCAL_POST_INSTALL_CMD := \
    ln -sf /system/bin $(TARGET_ROOT_OUT)/bin; \
    ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
    ln -sf /data/user_de/0/com.android.shell/files/bugreports $(TARGET_ROOT_OUT)/bugreports; \
    ln -sfn /sys/kernel/debug $(TARGET_ROOT_OUT)/d; \
    ln -sf /storage/self/primary $(TARGET_ROOT_OUT)/sdcard; \
    ln -sf /product/etc/security/adb_keys $(TARGET_ROOT_OUT)/adb_keys

ifndef BOARD_USES_VENDORIMAGE
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/vendor $(TARGET_ROOT_OUT)/vendor
endif
ifndef BOARD_USES_PRODUCTIMAGE
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/product $(TARGET_ROOT_OUT)/product
endif
ifndef BOARD_USES_SYSTEM_EXTIMAGE
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/system_ext $(TARGET_ROOT_OUT)/system_ext
endif

# For /odm partition.
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /odm partition. Those symlinks are for devices
# without /odm partition. For devices with /odm partition, mount odm.img under
# /odm will hide those symlinks.
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/app $(TARGET_ROOT_OUT)/odm/app
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/bin $(TARGET_ROOT_OUT)/odm/bin
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/etc $(TARGET_ROOT_OUT)/odm/etc
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/firmware $(TARGET_ROOT_OUT)/odm/firmware
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/framework $(TARGET_ROOT_OUT)/odm/framework
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/lib $(TARGET_ROOT_OUT)/odm/lib
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/lib64 $(TARGET_ROOT_OUT)/odm/lib64
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/overlay $(TARGET_ROOT_OUT)/odm/overlay
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/priv-app $(TARGET_ROOT_OUT)/odm/priv-app
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/usr $(TARGET_ROOT_OUT)/odm/usr

# For /vendor_dlkm partition.
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /vendor_dlkm partition. Those symlinks are for
# devices without /vendor_dlkm partition. For devices with /vendor_dlkm
# partition, mount vendor_dlkm.img under /vendor_dlkm will hide those symlinks.
# Note that /vendor_dlkm/lib is omitted because vendor DLKMs should be accessed
# via /vendor/lib/modules directly.
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/vendor_dlkm/etc $(TARGET_ROOT_OUT)/vendor_dlkm/etc

# For /odm_dlkm partition.
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /odm_dlkm partition. Those symlinks are for
# devices without /odm_dlkm partition. For devices with /odm_dlkm
# partition, mount odm_dlkm.img under /odm_dlkm will hide those symlinks.
# Note that /odm_dlkm/lib is omitted because odm DLKMs should be accessed
# via /odm/lib/modules directly.
LOCAL_POST_INSTALL_CMD += ; ln -sf /odm/odm_dlkm/etc $(TARGET_ROOT_OUT)/odm_dlkm/etc

ifndef BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE
  LOCAL_POST_INSTALL_CMD += ; ln -sf /data/cache $(TARGET_ROOT_OUT)/cache
endif
ifdef BOARD_ROOT_EXTRA_SYMLINKS
# BOARD_ROOT_EXTRA_SYMLINKS is a list of <target>:<link_name>.
  LOCAL_POST_INSTALL_CMD += $(foreach s, $(BOARD_ROOT_EXTRA_SYMLINKS),\
    $(eval p := $(subst :,$(space),$(s)))\
    ; ln -sf $(word 1,$(p)) $(TARGET_ROOT_OUT)/$(word 2,$(p)))
endif

# The init symlink must be a post install command of a file that is to TARGET_ROOT_OUT.
# Since init.environ.rc is required for init and satisfies that requirement, we hijack it to create the symlink.
LOCAL_POST_INSTALL_CMD += ; ln -sf /system/bin/init $(TARGET_ROOT_OUT)/init
ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/init

ALL_DEFAULT_INSTALLED_MODULES += $(ALL_ROOTDIR_SYMLINKS)

include $(BUILD_SYSTEM)/base_rules.mk

init.environ.rc-soong := $(call intermediates-dir-for,ETC,init.environ.rc-soong)/init.environ.rc-soong
$(eval $(call copy-one-file,$(init.environ.rc-soong),$(LOCAL_BUILT_MODULE)))
init.environ.rc-soong :=
