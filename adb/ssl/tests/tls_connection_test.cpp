/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "AdbWifiTlsConnectionTest"

#include <thread>

#include <gtest/gtest.h>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <adb/ssl/tls_connection.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

using namespace adb::crypto;

namespace adb {
namespace ssl {

using android::base::unique_fd;

// Test X.509 certificates (RSA 2048)

class AdbWifiTlsConnectionTest : public testing::Test {
  protected:
    virtual void SetUp() override {
        GenerateCertificate(testRsa2048ServerCert, testRsa2048ServerPrivKey);
        GenerateCertificate(testRsa2048ClientCert, testRsa2048ClientPrivKey);
        android::base::Socketpair(SOCK_STREAM, &server_fd_, &client_fd_);
        server_ = TlsConnection::Create(TlsConnection::Role::Server, testRsa2048ServerCert,
                                        testRsa2048ServerPrivKey);
        client_ = TlsConnection::Create(TlsConnection::Role::Client, testRsa2048ClientCert,
                                        testRsa2048ClientPrivKey);
        ASSERT_NE(nullptr, server_);
        ASSERT_NE(nullptr, client_);
    }

    virtual void TearDown() override {
        WaitForClientConnection();
        // Shutdown the SSL connection first.
        server_.reset();
        client_.reset();
    }

    void GenerateCertificate(std::string& cert, std::string& priv_key) {
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

    void SetupClientConnectionAsync(bool use_cert_verify) {
        client_thread_ = std::thread([=]() {
            client_->EnableCertificateVerification(use_cert_verify);
            if (!client_->DoHandshake(client_fd_.get())) {
                return;
            }
        });
    }

    void WaitForClientConnection() {
        if (client_thread_.joinable()) {
            client_thread_.join();
        }
    }

    unique_fd server_fd_;
    unique_fd client_fd_;
    const std::string msg_ = "hello world";
    std::unique_ptr<TlsConnection> server_;
    std::unique_ptr<TlsConnection> client_;
    std::thread client_thread_;
    std::string testRsa2048ServerCert;
    std::string testRsa2048ServerPrivKey;
    std::string testRsa2048ClientCert;
    std::string testRsa2048ClientPrivKey;
};

TEST_F(AdbWifiTlsConnectionTest, NoCertificateVerification) {
    server_->EnableCertificateVerification(false);
    SetupClientConnectionAsync(false);

    // Handshake should succeed
    EXPECT_TRUE(server_->DoHandshake(server_fd_.get()));
    WaitForClientConnection();

    // Client write, server read
    EXPECT_TRUE(client_->WriteFully(msg_));
    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));

    // Client read, server write
    EXPECT_TRUE(server_->WriteFully(msg_));
    data = client_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));
}

TEST_F(AdbWifiTlsConnectionTest, NoTrustedCertificates) {
    server_->EnableCertificateVerification(true);
    SetupClientConnectionAsync(true);

    // Handshake should not succeed
    ASSERT_FALSE(server_->DoHandshake(server_fd_.get()));
    WaitForClientConnection();

    // Client write, server read should fail
    EXPECT_FALSE(client_->WriteFully(msg_));
    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), 0);

    // Client read, server write should fail
    EXPECT_FALSE(server_->WriteFully(msg_));
    data = client_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), 0);
}

TEST_F(AdbWifiTlsConnectionTest, AddTrustedCertificates) {
    server_->EnableCertificateVerification(true);

    // Add peer certificates
    EXPECT_TRUE(client_->AddTrustedCertificate(testRsa2048ServerCert));
    EXPECT_TRUE(server_->AddTrustedCertificate(testRsa2048ClientCert));

    SetupClientConnectionAsync(true);

    // Handshake should succeed
    EXPECT_TRUE(server_->DoHandshake(server_fd_.get()));
    WaitForClientConnection();

    // Client write, server read
    EXPECT_TRUE(client_->WriteFully(msg_));
    auto data = server_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));

    // Client read, server write
    EXPECT_TRUE(server_->WriteFully(msg_));
    data = client_->ReadFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));
}

TEST_F(AdbWifiTlsConnectionTest, ExportKeyingMaterial) {
    server_->EnableCertificateVerification(false);

    // Add peer certificates
    EXPECT_TRUE(client_->AddTrustedCertificate(testRsa2048ServerCert));
    EXPECT_TRUE(server_->AddTrustedCertificate(testRsa2048ClientCert));

    SetupClientConnectionAsync(true);

    // Handshake should succeed
    EXPECT_TRUE(server_->DoHandshake(server_fd_.get()));
    WaitForClientConnection();

    // Verify the client and server's exported key material match.
    const size_t keySize = 64;
    auto clientKeyMaterial = client_->ExportKeyingMaterial(keySize);
    ASSERT_TRUE(!clientKeyMaterial.empty());
    auto serverKeyMaterial = server_->ExportKeyingMaterial(keySize);
    ASSERT_TRUE(!serverKeyMaterial.empty());
    ASSERT_EQ(clientKeyMaterial.size(), keySize);
    ASSERT_EQ(clientKeyMaterial.size(), serverKeyMaterial.size());
    EXPECT_EQ(memcmp(clientKeyMaterial.data(), serverKeyMaterial.data(), clientKeyMaterial.size()),
              0);
}

}  // namespace ssl
}  // namespace adb
