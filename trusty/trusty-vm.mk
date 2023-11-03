#
# Copyright (C) 2023 The Android Open-Source Project
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
# This makefile should be included by devices that use Trusty TEE in a vm
# to pull in the trusty vm config and image.
#

PRODUCT_PACKAGES += \
    trusty_vm \
    trusty_vm_lk_elf \
    crosvm_vendor \

# trusty vm in android with cid 4
PRODUCT_PROPERTY_OVERRIDES += \
    ro.hardware.trusty_vm_cid=4 \
    ro.hardware.trusty_ipc_dev=VSOCK:4:1 \

