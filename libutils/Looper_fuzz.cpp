/*
 * Copyright 2020 The Android Open Source Project
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

#include <sys/select.h>

#include <iostream>

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/Looper.h"

using android::Looper;
using android::sp;

// We don't want this to bog down fuzzing
static constexpr int MAX_POLL_DELAY = 50;
static constexpr int MAX_OPERATIONS = 500;

// Modified version of Pipe from Looper_test.cpp that adds timeouts. Is there a
// better way to include this dependency?
class Pipe {
  public:
    int sendFd;
    int receiveFd;

    Pipe() {
        int fds[2];
        ::pipe(fds);

        receiveFd = fds[0];
        sendFd = fds[1];
    }

    ~Pipe() {
        if (sendFd != -1) {
            ::close(sendFd);
        }

        if (receiveFd != -1) {
            ::close(receiveFd);
        }
    }

    android::status_t writeSignal() {
        ssize_t nWritten = ::write(sendFd, "*", 1);
        return nWritten == 1 ? 0 : -errno;
    }

    android::status_t readSignal() {
        fd_set set;
        // For fuzzing we will add a timeout when reading (there may not be input!)
        struct timeval timeout;
        FD_ZERO(&set);
        FD_SET(receiveFd, &set);
        timeout.tv_sec = 0;
        timeout.tv_usec = 5000;

        int val = select(receiveFd + 1, &set, NULL, NULL, &timeout);
        if (val == -1) {
            perror("select");
            return -errno;
        } else if (val == 0) {
            return -EPIPE;
        }

        char buf[1];
        ssize_t nRead = ::read(receiveFd, buf, 1);
        return nRead == 1 ? 0 : nRead == 0 ? -EPIPE : -errno;
    }
};

void doNothing() {}
void* doNothingPointer = reinterpret_cast<void*>(doNothing);

static int noopCallback(int, int, void*) {
    return 0;
}

std::vector<std::function<void(FuzzedDataProvider*, sp<Looper>, Pipe)>> operations = {
        [](FuzzedDataProvider* dataProvider, sp<Looper> looper, Pipe) -> void {
            looper->pollOnce(dataProvider->ConsumeIntegralInRange<int>(0, MAX_POLL_DELAY));
        },
        [](FuzzedDataProvider* dataProvider, sp<Looper> looper, Pipe) -> void {
            looper->pollAll(dataProvider->ConsumeIntegralInRange<int>(0, MAX_POLL_DELAY));
        },
        // events and callback are nullptr
        [](FuzzedDataProvider* dataProvider, sp<Looper> looper, Pipe pipeObj) -> void {
            looper->addFd(pipeObj.receiveFd, dataProvider->ConsumeIntegral<int>(),
                          dataProvider->ConsumeIntegral<int>(), nullptr, nullptr);
        },
        // Events is nullptr
        [](FuzzedDataProvider* dataProvider, sp<Looper> looper, Pipe pipeObj) -> void {
            looper->addFd(pipeObj.receiveFd, dataProvider->ConsumeIntegral<int>(),
                          dataProvider->ConsumeIntegral<int>(), noopCallback, nullptr);
        },
        // callback is nullptr
        [](FuzzedDataProvider* dataProvider, sp<Looper> looper, Pipe pipeObj) -> void {
            looper->addFd(pipeObj.receiveFd, dataProvider->ConsumeIntegral<int>(),
                          dataProvider->ConsumeIntegral<int>(), nullptr, doNothingPointer);
        },
        // callback and events both set
        [](FuzzedDataProvider* dataProvider, sp<Looper> looper, Pipe pipeObj) -> void {
            looper->addFd(pipeObj.receiveFd, dataProvider->ConsumeIntegral<int>(),
                          dataProvider->ConsumeIntegral<int>(), noopCallback, doNothingPointer);
        },

        [](FuzzedDataProvider*, sp<Looper> looper, Pipe) -> void { looper->wake(); },
        [](FuzzedDataProvider*, sp<Looper>, Pipe pipeObj) -> void { pipeObj.writeSignal(); },
        [](FuzzedDataProvider*, sp<Looper>, Pipe pipeObj) -> void { pipeObj.readSignal(); },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Pipe pipeObj;
    FuzzedDataProvider dataProvider(data, size);
    sp<Looper> looper = new Looper(dataProvider.ConsumeBool());

    size_t opsRun = 0;
    while (dataProvider.remaining_bytes() > 0 && opsRun++ < MAX_OPERATIONS) {
        uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
        operations[op](&dataProvider, looper, pipeObj);
    }
    // Clear our pointer
    looper.clear();
    return 0;
}
