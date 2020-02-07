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

#define LOG_TAG "AdbPairingConnectionTest"

#include <condition_variable>
#include <mutex>
#include <thread>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <adb/pairing/pairing_server.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "pairing_client.h"

using namespace adb::crypto;

namespace adb {
namespace pairing {

struct ServerDeleter {
    void operator()(PairingServerCtx* p) { pairing_server_destroy(p); }
};
using ServerPtr = std::unique_ptr<PairingServerCtx, ServerDeleter>;

struct ResultWaiter {
    std::mutex mutex_;
    std::condition_variable cv_;
    std::optional<bool> is_valid_;
    PeerInfo peer_info_;

    static void ResultCallback(const PeerInfo* peer_info, void* opaque) {
        auto* p = reinterpret_cast<ResultWaiter*>(opaque);
        {
            std::unique_lock<std::mutex> lock(p->mutex_);
            if (peer_info) {
                memcpy(&(p->peer_info_), peer_info, sizeof(PeerInfo));
            }
            p->is_valid_ = (peer_info != nullptr);
        }
        p->cv_.notify_one();
    }
};

class AdbPairingConnectionTest : public testing::Test {
  protected:
    virtual void SetUp() override {
        GenerateCertificate(kTestServerCert, kTestServerPrivKey);
        GenerateCertificate(kTestClientCert, kTestClientPrivKey);
    }

    virtual void TearDown() override {}

    void InitPairing(const std::vector<uint8_t>& server_pswd,
                     const std::vector<uint8_t>& client_pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestServerCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestServerCert.data()) +
                            kTestServerCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()) +
                           kTestServerPrivKey.size() + 1);
        server_ = CreateServer(server_pswd, server_info_, cert, key, 0);
        cert.assign(reinterpret_cast<const uint8_t*>(kTestClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestClientCert.data()) +
                            kTestClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()) +
                           kTestClientPrivKey.size() + 1);
        client_ = PairingClient::Create(client_pswd, client_info_, cert, key);
    }

    ServerPtr createServer(const std::vector<uint8_t>& pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestServerCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestServerCert.data()) +
                            kTestServerCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()) +
                           kTestServerPrivKey.size() + 1);
        return CreateServer(pswd, server_info_, cert, key, 0);
    }

    std::unique_ptr<PairingClient> createClient(const std::vector<uint8_t> pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestClientCert.data()) +
                            kTestClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()) +
                           kTestClientPrivKey.size() + 1);
        return PairingClient::Create(pswd, client_info_, cert, key);
    }

    static void GenerateCertificate(std::string& cert, std::string& priv_key) {
        auto rsa_2048 = CreateRSA2048Key();

        std::string pub_key_plus_name;
        auto* rsa = EVP_PKEY_get0_RSA(rsa_2048->GetEvpPkey());
        ASSERT_TRUE(CalculatePublicKey(&pub_key_plus_name, rsa));
        std::vector<std::string> split =
                android::base::Split(std::string(pub_key_plus_name), " \t");
        ASSERT_EQ(split.size(), 2);

        LOG(INFO) << "pub_key=[" << pub_key_plus_name << "]";
        auto x509_cert = GenerateX509Certificate(rsa_2048->GetEvpPkey());
        ASSERT_NE(x509_cert.get(), nullptr);

        cert = X509ToPEMString(x509_cert.get());
        ASSERT_FALSE(cert.empty());
        priv_key = Key::ToPEMString(rsa_2048->GetEvpPkey());
        ASSERT_FALSE(priv_key.empty());
    }

    static ServerPtr CreateServer(const std::vector<uint8_t>& pswd, const PeerInfo& peer_info,
                                  const std::vector<uint8_t>& cert,
                                  const std::vector<uint8_t>& priv_key, int port) {
        return ServerPtr(pairing_server_new(pswd.data(), pswd.size(), peer_info, cert.data(),
                                            cert.size(), priv_key.data(), priv_key.size(), port));
    }

    ServerPtr server_;
    const PeerInfo server_info_ = {
            .info = "my_server_info",
    };
    std::unique_ptr<PairingClient> client_;
    const PeerInfo client_info_ = {
            .info = "my_client_info",
    };
    std::string ip_addr_ = "127.0.0.1:";
    std::string kTestServerCert;
    std::string kTestServerPrivKey;
    std::string kTestClientCert;
    std::string kTestClientPrivKey;
};

TEST_F(AdbPairingConnectionTest, ServerCreation) {
    // All parameters bad
    ASSERT_DEATH({ auto server = CreateServer({}, {}, {}, {}, 0); }, "");
    // Bad password
    ASSERT_DEATH({ auto server = CreateServer({}, server_info_, {0x01}, {0x01}, 0); }, "");
    // Bad peer_info
    ASSERT_DEATH({ auto server = CreateServer({0x01}, {}, {0x01}, {0x01}, 0); }, "");
    // Bad certificate
    ASSERT_DEATH({ auto server = CreateServer({0x01}, server_info_, {}, {0x01}, 0); }, "");
    // Bad private key
    ASSERT_DEATH({ auto server = CreateServer({0x01}, server_info_, {0x01}, {}, 0); }, "");
    // Valid params
    auto server = CreateServer({0x01}, server_info_, {0x01}, {0x01}, 0);
    EXPECT_NE(nullptr, server);
}

TEST_F(AdbPairingConnectionTest, ClientCreation) {
    // All parameters bad
    ASSERT_DEATH({ auto client = PairingClient::Create({}, client_info_, {}, {}); }, "");
    // Bad password
    ASSERT_DEATH({ auto client = PairingClient::Create({}, client_info_, {0x01}, {0x01}); }, "");
    // Bad peer_info
    ASSERT_DEATH({ auto client = PairingClient::Create({0x01}, {}, {0x01}, {0x01}); }, "");
    // Bad certificate
    ASSERT_DEATH({ auto client = PairingClient::Create({0x01}, client_info_, {}, {0x01}); }, "");
    // Bad private key
    ASSERT_DEATH({ auto client = PairingClient::Create({0x01}, client_info_, {0x01}, {}); }, "");
    // Valid params
    auto client = PairingClient::Create({0x01}, client_info_, {0x01}, {0x01});
    EXPECT_NE(nullptr, client);
}

TEST_F(AdbPairingConnectionTest, SmokeValidPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    InitPairing(pswd, pswd);

    // Start the server
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server_.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start the client
    ResultWaiter client_waiter;
    std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
    ASSERT_TRUE(client_->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
    client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
    ASSERT_TRUE(*(client_waiter.is_valid_));
    ASSERT_EQ(strlen(client_waiter.peer_info_.info), strlen(server_info_.info));
    EXPECT_EQ(memcmp(client_waiter.peer_info_.info, server_info_.info, strlen(server_info_.info)),
              0);

    // Kill server if the pairing failed, since server only shuts down when
    // it gets a valid pairing.
    if (!client_waiter.is_valid_) {
        server_lock.unlock();
        server_.reset();
    } else {
        server_waiter.cv_.wait(server_lock, [&]() { return server_waiter.is_valid_.has_value(); });
        ASSERT_TRUE(*(server_waiter.is_valid_));
        ASSERT_EQ(strlen(server_waiter.peer_info_.info), strlen(client_info_.info));
        EXPECT_EQ(
                memcmp(server_waiter.peer_info_.info, client_info_.info, strlen(client_info_.info)),
                0);
    }
}

TEST_F(AdbPairingConnectionTest, CancelPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};
    InitPairing(pswd, pswd2);

    // Start the server
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server_.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start the client. Client should fail to pair
    ResultWaiter client_waiter;
    std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
    ASSERT_TRUE(client_->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
    client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
    ASSERT_FALSE(*(client_waiter.is_valid_));

    // Kill the server. We should still receive the callback with no valid
    // pairing.
    server_lock.unlock();
    server_.reset();
    server_lock.lock();
    ASSERT_TRUE(server_waiter.is_valid_.has_value());
    EXPECT_FALSE(*(server_waiter.is_valid_));
}

TEST_F(AdbPairingConnectionTest, MultipleClientsAllFail) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    // Start the server
    auto server = createServer(pswd);
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start multiple clients, all with bad passwords
    int test_num_clients = 5;
    int num_clients_done = 0;
    std::mutex global_clients_mutex;
    std::unique_lock<std::mutex> global_clients_lock(global_clients_mutex);
    std::condition_variable global_cv_;
    for (int i = 0; i < test_num_clients; ++i) {
        std::thread([&]() {
            auto client = createClient(pswd2);
            ResultWaiter client_waiter;
            std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
            ASSERT_TRUE(client->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
            client_waiter.cv_.wait(client_lock,
                                   [&]() { return client_waiter.is_valid_.has_value(); });
            ASSERT_FALSE(*(client_waiter.is_valid_));
            {
                std::lock_guard<std::mutex> global_lock(global_clients_mutex);
                ++num_clients_done;
            }
            global_cv_.notify_one();
        }).detach();
    }

    global_cv_.wait(global_clients_lock, [&]() { return num_clients_done == test_num_clients; });
    server_lock.unlock();
    server.reset();
    server_lock.lock();
    ASSERT_TRUE(server_waiter.is_valid_.has_value());
    EXPECT_FALSE(*(server_waiter.is_valid_));
}

TEST_F(AdbPairingConnectionTest, MultipleClientsOnePass) {
    // Send multiple clients with bad passwords, but send the last one with the
    // correct password.
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    // Start the server
    auto server = createServer(pswd);
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start multiple clients, all with bad passwords
    int test_num_clients = 5;
    int num_clients_done = 0;
    std::mutex global_clients_mutex;
    std::unique_lock<std::mutex> global_clients_lock(global_clients_mutex);
    std::condition_variable global_cv_;
    for (int i = 0; i < test_num_clients; ++i) {
        std::thread([&, i]() {
            bool good_client = (i == (test_num_clients - 1));
            auto client = createClient((good_client ? pswd : pswd2));
            ResultWaiter client_waiter;
            std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
            ASSERT_TRUE(client->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
            client_waiter.cv_.wait(client_lock,
                                   [&]() { return client_waiter.is_valid_.has_value(); });
            if (good_client) {
                ASSERT_TRUE(*(client_waiter.is_valid_));
                ASSERT_EQ(strlen(client_waiter.peer_info_.info), strlen(server_info_.info));
                EXPECT_EQ(memcmp(client_waiter.peer_info_.info, server_info_.info,
                                 strlen(server_info_.info)),
                          0);
            } else {
                ASSERT_FALSE(*(client_waiter.is_valid_));
            }
            {
                std::lock_guard<std::mutex> global_lock(global_clients_mutex);
                ++num_clients_done;
            }
            global_cv_.notify_one();
        }).detach();
    }

    global_cv_.wait(global_clients_lock, [&]() { return num_clients_done == test_num_clients; });
    server_waiter.cv_.wait(server_lock, [&]() { return server_waiter.is_valid_.has_value(); });
    ASSERT_TRUE(*(server_waiter.is_valid_));
    ASSERT_EQ(strlen(server_waiter.peer_info_.info), strlen(client_info_.info));
    EXPECT_EQ(memcmp(server_waiter.peer_info_.info, client_info_.info, strlen(client_info_.info)),
              0);
}

}  // namespace pairing
}  // namespace adb
