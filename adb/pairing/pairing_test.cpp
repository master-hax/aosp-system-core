/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include <gtest/gtest.h>

#include "crypto/key_store.h"
#include "fdevent_test.h"
#include "pairing/pairing_client.h"
#include "pairing/pairing_server.h"

class PairingTest : public FdeventTest {
protected:
    template<class T>
    using Optional = std::pair<bool, T>;

    void clientStatus(bool success) {
        std::unique_lock<std::mutex> lock(mutex_);
        clientResult_ = Optional<bool>(true, success);
        condition_.notify_all();
    }
    void serverStatus(bool success) {
        std::unique_lock<std::mutex> lock(mutex_);
        serverResult_ = Optional<bool>(true, success);
        condition_.notify_all();
    }

    std::condition_variable condition_;
    std::mutex mutex_;
    Optional<bool> clientResult_;
    Optional<bool> serverResult_;
};

TEST_F(PairingTest, connect) {
    ASSERT_TRUE(initKeyStore());

    const char password[] = "password";
    auto clientCallback = [this](bool success) { this->clientStatus(success); };
    auto serverCallback = [this](bool success) { this->serverStatus(success); };
    auto client = std::make_unique<PairingClient>(password, clientCallback);
    auto server = std::make_unique<PairingServer>(password, serverCallback);

    std::string response;
    ASSERT_TRUE(server->listen(&response, 5013));
    ASSERT_TRUE(response.empty());

    ASSERT_TRUE(client->connect("localhost", 5013, &response));
    ASSERT_TRUE(response.empty());

    PrepareThread();

    std::unique_lock<std::mutex> lock(mutex_);
    for (int i = 0; !clientResult_.first && !serverResult_.first && i < 2; ++i) {
        ASSERT_EQ(std::cv_status::no_timeout,
                  condition_.wait_for(lock, std::chrono::seconds(3)));
    }
              
    ASSERT_TRUE(clientResult_.first);
    ASSERT_TRUE(serverResult_.first);

    EXPECT_TRUE(clientResult_.second);
    EXPECT_TRUE(serverResult_.second);
}
