/*
 * Copyright (C) 2018 The Android Open Source Project
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
#pragma once

#define FB_CMD_GETVAR "getvar"
#define FB_CMD_DOWNLOAD "download"
#define FB_CMD_UPLOAD "upload"
#define FB_CMD_VERIFY "verify"
#define FB_CMD_FLASH "flash"
#define FB_CMD_ERASE "erase"
#define FB_CMD_BOOT "boot"
#define FB_CMD_SET_ACTIVE "set_active"
#define FB_CMD_CONTINUE "continue"
#define FB_CMD_REBOOT "reboot"
#define FB_CMD_SHUTDOWN "shutdown"
#define FB_CMD_REBOOT_BOOTLOADER "reboot-bootloader"
#define FB_CMD_POWERDOWN "powerdown"


#define FB_VAR_VERSION "version"
#define FB_VAR_VERSION_BOOTLOADER "version-bootloader"
#define FB_VAR_VERSION_BASEBAND "version-baseband"
#define FB_VAR_PRODUCT "product"
#define FB_VAR_SERIALNO "serialno"
#define FB_VAR_SECURE "secure"
#define FB_VAR_UNLOCKED "unlocked"
#define FB_VAR_CURRENT_SLOT "current-slot"
#define FB_VAR_MAX_DOWNLOAD_SIZE "max-download-size"
#define FB_VAR_HAS_SLOT "has-slot"
#define FB_VAR_SLOT_COUNT "slot-count"
#define FB_VAR_PARTITION_SIZE "partition-size"
