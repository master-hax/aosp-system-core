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
    InitKeychordsFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void process();

  private:
    void InvokeKeychord();
    void InvokeMountHandler();
    void InvokeHandlerRegister();
    void InvokeCall();
    FuzzedDataProvider fdp_;
    Epoll epoll_;
};

void InitKeychordsFuzzer::InvokeCall() {
    auto results = epoll_.Wait(
            std::chrono::milliseconds(fdp_.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize)));
    for (const auto& function : results.value()) {
        if (function) {
            (*function)();
        }
    }
}

void InitKeychordsFuzzer::InvokeMountHandler() {
    MountHandler mount_handler(&epoll_);
    /**
     * REMOUNT is done to trigger EPOLLERR | EPOLLPRI which will trigger the
     * mount handler callback and it requires root permission (via adb root)
     */
    mount(kSource.c_str(), kTarget.c_str(), kFileSystemType.c_str(), MS_REMOUNT, nullptr);
    InvokeCall();
}

void InitKeychordsFuzzer::InvokeHandlerRegister() {
    int32_t fds[kSize];
    pipe(fds);
    epoll_.RegisterHandler(fds[0], [&]() -> void { epoll_.UnregisterHandler(fds[0]); });
    uint8_t byte = fdp_.ConsumeIntegralInRange<uint8_t>(kMinSize, kMaxBytes);
    android::base::WriteFully(fds[1], &byte, sizeof(byte));
    InvokeCall();
}

void InitKeychordsFuzzer::InvokeKeychord() {
    Keychords keychords;
    for (size_t idx = 0; idx < fdp_.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idx) {
        std::vector<int32_t> keycodes;
        for (size_t idy = 0; idy < fdp_.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idy) {
            keycodes.push_back(fdp_.ConsumeIntegralInRange<uint32_t>(kMinSize, kMaxSize));
        }
        keychords.Register(keycodes);
    }
    keychords.Start(&epoll_, [&](const std::vector<int32_t>&) {});
}

void InitKeychordsFuzzer::process() {
    while (fdp_.remaining_bytes()) {
        epoll_.Open();
        auto keychord_function = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() { InvokeKeychord(); },
                [&]() { InvokeMountHandler(); },
                [&]() { InvokeHandlerRegister(); },
        });
        keychord_function();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitKeychordsFuzzer init_keychords_fuzzer(data, size);
    init_keychords_fuzzer.process();
    return 0;
}
