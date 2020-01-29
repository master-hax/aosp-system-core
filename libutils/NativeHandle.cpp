/*
 * Copyright 2014 The Android Open Source Project
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

#include <utils/NativeHandle.h>
#include <cutils/native_handle.h>

#include <unistd.h>

namespace android {

sp<NativeHandle> NativeHandle::create(native_handle_t* handle, bool ownsHandle) {
    return handle ? new NativeHandle(handle, ownsHandle) : nullptr;
}

NativeHandle::NativeHandle(native_handle_t* handle, bool ownsHandle)
        : mHandle(handle), mOwnsHandle(ownsHandle) {

}

NativeHandle::~NativeHandle() {
    if (mOwnsHandle && mHandle) {
        // Copied from libcutils, since this is the last libutils dependency on
        // libutils.
        if (mHandle->version != sizeof(native_handle_t)) return;
        const int numFds = mHandle->numFds;
        for (int i = 0; i < numFds; ++i) {
            close(mHandle->data[i]);
        }
        free(mHandle);
    }
}

} // namespace android
