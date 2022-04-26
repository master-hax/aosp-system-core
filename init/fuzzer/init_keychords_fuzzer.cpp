/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android-base/file.h>
#include <epoll.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <keychords.h>
#include <mount_handler.h>
#include <sys/mount.h>

using namespace android;
using namespace android::init;
constexpr int32_t kMaxSize = 1000;
constexpr int32_t kMinSize = 0;
constexpr int32_t kSize = 2;
constexpr int32_t kMaxBytes = 10;
const std::string kSource = "/";
const std::string kTarget = "/data";
const std::string kFileSystemType = "proc";

class InitKeychordsFuzzer {
  public:
    InitKeychordsFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void invokeKeychord();
    void invokeMountHandler();
    void invokeHandlerRegister();
    void invokeCall();
    FuzzedDataProvider mFdp;
    Epoll mEpoll;
};

void InitKeychordsFuzzer::invokeCall() {
    auto results = mEpoll.Wait(
            std::chrono::milliseconds(mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize)));
    for (const auto& function : results.value()) {
        if (function) {
            (*function)();
        }
    }
}

void InitKeychordsFuzzer::invokeMountHandler() {
    MountHandler mountHandler(&mEpoll);
    /**
     * REMOUNT is done to trigger EPOLLERR | EPOLLPRI which will trigger the
     * mount handler callback and it requires root permission (via adb root)
     */
    mount(kSource.c_str(), kTarget.c_str(), kFileSystemType.c_str(), MS_REMOUNT, nullptr);
    invokeCall();
}

void InitKeychordsFuzzer::invokeHandlerRegister() {
    int32_t fds[kSize];
    pipe(fds);
    mEpoll.RegisterHandler(fds[0], [&]() -> void { mEpoll.UnregisterHandler(fds[0]); });
    uint8_t byte = mFdp.ConsumeIntegralInRange<uint8_t>(kMinSize, kMaxBytes);
    android::base::WriteFully(fds[1], &byte, sizeof(byte));
    invokeCall();
}

void InitKeychordsFuzzer::invokeKeychord() {
    Keychords keychords;
    for (size_t idx = 0; idx < mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idx) {
        std::vector<int32_t> keycodes;
        for (size_t idy = 0; idy < mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idy) {
            keycodes.push_back(mFdp.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize));
        }
        keychords.Register(keycodes);
    }
    keychords.Start(&mEpoll, [&](const std::vector<int32_t>&) {});
}

void InitKeychordsFuzzer::process() {
    while (mFdp.remaining_bytes()) {
        mEpoll.Open();
        auto keychordFunction = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { invokeKeychord(); },
                [&]() { invokeMountHandler(); },
                [&]() { invokeHandlerRegister(); },
        });
        keychordFunction();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitKeychordsFuzzer initKeychordsFuzzer(data, size);
    initKeychordsFuzzer.process();
    return 0;
}
