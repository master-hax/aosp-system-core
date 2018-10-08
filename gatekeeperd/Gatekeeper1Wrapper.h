/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef GATEKEEPER1_WRAPPER_H_
#define GATEKEEPER1_WRAPPER_H_

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <android/hardware/gatekeeper/2.0/IGatekeeper.h>

::android::sp<::android::hardware::gatekeeper::V2_0::IGatekeeper> wrapGatekeeper1(
        ::android::sp<::android::hardware::gatekeeper::V1_0::IGatekeeper> gk1);

#endif  // GATEKEEPER1_WRAPPER_H_
