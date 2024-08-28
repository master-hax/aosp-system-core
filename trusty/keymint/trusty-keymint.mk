#
# Copyright (C) 2024 The Android Open-Source Project
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

#
# This makefile should be included by devices that use Trusty VM or TEE
# to pull in the baseline set of Keymint HAL specific modules.
#

# Allow the KeyMint HAL service implementation to be selected at build time.  This needs to be
# done in sync with the TA implementation included in Trusty.  Possible values are:
#
# - Rust implementation:   export TRUSTY_KEYMINT_IMPL=rust
# - C++ implementation:    (any other value of TRUSTY_KEYMINT_IMPL)

ifeq ($(TRUSTY_KEYMINT_IMPL),rust)
    ifdef TRUSTY_SYSTEM_VM
    ifeq ($(TRUSTY_SYSTEM_VM), nonsecure)
        # Select the nonsecure system HALs (accessing the system Trusty VM)
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty.system.nonsecure
    else
    # Default to the secure system HALs (accessing the system Trusty pVM)
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty.system
    endif
    else # ifdef TRUSTY_SYSTEM_VM
    # vendor hal accessing Keymint in Trusty TEE
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty
    endif # ifdef TRUSTY_SYSTEM_VM
else
    # Default to the C++ implementation
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.trusty
    ifdef # ifdef TRUSTY_SYSTEM_VM
        $(error TRUSTY_SYSTEM_VM requires TRUSTY_KEYMINT_IMPL=rust)
    endif
endif
PRODUCT_PROPERTY_OVERRIDES += \
	ro.hardware.keystore_desede=true \
	ro.hardware.keystore=trusty \

PRODUCT_PACKAGES += \
	$(LOCAL_KEYMINT_PRODUCT_PACKAGE) \

ifdef TRUSTY_VM_IN_SYSTEM
PRODUCT_COPY_FILES += \
	frameworks/native/data/etc/android.hardware.keystore.app_attest_key.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/permissions/android.hardware.keystore.app_attest_key.xml
else
PRODUCT_COPY_FILES += \
	frameworks/native/data/etc/android.hardware.keystore.app_attest_key.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.keystore.app_attest_key.xml
endif
