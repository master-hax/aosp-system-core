/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "DEBUG"

#include "libdebuggerd/utility.h"

#include <sys/prctl.h>

#include <string>

#include <android-base/stringprintf.h>

using android::base::StringPrintf;

#define DESCRIBE_FLAG(flag) \
  if (value & flag) {       \
    desc += ", ";           \
    desc += #flag;          \
    value &= ~flag;         \
  }

std::string describe_tagged_addr_ctrl(long value) {
  std::string desc;
  DESCRIBE_FLAG(PR_TAGGED_ADDR_ENABLE);
  DESCRIBE_FLAG(PR_MTE_TCF_SYNC);
  DESCRIBE_FLAG(PR_MTE_TCF_ASYNC);
  if (value & PR_MTE_TAG_MASK) {
    desc += StringPrintf(", mask 0x%04lx", (value & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT);
    value &= ~PR_MTE_TAG_MASK;
  }
  return describe_end(value, desc);
}

std::string describe_pac_enabled_keys(long value) {
  std::string desc;
  DESCRIBE_FLAG(PR_PAC_APIAKEY);
  DESCRIBE_FLAG(PR_PAC_APIBKEY);
  DESCRIBE_FLAG(PR_PAC_APDAKEY);
  DESCRIBE_FLAG(PR_PAC_APDBKEY);
  DESCRIBE_FLAG(PR_PAC_APGAKEY);
  return describe_end(value, desc);
}

std::string describe_end(long value, std::string& desc) {
  if (value) {
    desc += StringPrintf(", unknown 0x%lx", value);
  }
  return desc.empty() ? "" : " (" + desc.substr(2) + ")";
}
