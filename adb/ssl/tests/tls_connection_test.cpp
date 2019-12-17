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

#include <adb/ssl/tls_connection.h>
#include <android-base/unique_fd.h>

namespace adb {
namespace ssl {

using android::base::unique_fd;

// Test X.509 certificates (RSA 2048)
static const std::string kTestRsa2048ServerCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTE5MTIyMDAzNTQyMloX\n"
        "DTI5MTIxNzAzNTQyMlowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALE7\n"
        "EgJhJalrCDbgKdOqSwePwC157+RqiNvEOXQOQKTaFKKPWrYosSpLzbmlAiAAIOKT\n"
        "LteNneGB6zdFWr6mm1Ssttwc4BbN5wFQ+66yW93H6B5dq65EavEb1MIHMcwkk/d0\n"
        "bndOqyDOIyym6vJwmS1BT9nDg7Re4BRB33hY2FF6Y5CS195HMn8ShvRN8sxEhCCL\n"
        "JIR1afhuAzbiG9TWs5KZ06e6zsh3HS3y9NXqiuddUTOC8KtdKShRRmPvk4oI3uSH\n"
        "YqyNZgSo1iIEluRLQgG5mMooA+aYxlroGvI1kmnkl1v6XjKucq1h555Alacl9kch\n"
        "xkeqVCAN5oLL1yA1/yUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCASYwHQYDVR0OBBYEFA8aG7W6SipEX975/LaTtq0z92/eMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQAOCwl/VX2saYkwWOJZSd/zYsiChyc7PwZ1PifPkL1wsb1Jqgs7\n"
        "6cZNjQafLnriU+oreGswn+XjrUQWVzgXXk2dqXZ2N7vxzq0IjKYb2OyrbHESDJdh\n"
        "qzc6GdyKuH/7uUyiMmRCDyzd6G4a1XDG7LJvmhFcq2s0UB64Cvh1fFU9QI15ud7N\n"
        "ZRX6fpjPtrVwemORDglols+XrfDYK5aT1KLEGVoN8U73bIsMpv5asvG0jkDQdQBo\n"
        "LMgZbjpBsJhrFALJidFDBuGGu8mSnXQgYaXouDVxsWaOFtwt6MUSFinjcWO95WWg\n"
        "QQBYLdziavymQ38EmzDDGyZYuq1qFIeow/IF\n"
        "-----END CERTIFICATE-----";

static const std::string kTestRsa2048ServerPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxOxICYSWpawg2\n"
        "4CnTqksHj8Atee/kaojbxDl0DkCk2hSij1q2KLEqS825pQIgACDiky7XjZ3hges3\n"
        "RVq+pptUrLbcHOAWzecBUPuuslvdx+geXauuRGrxG9TCBzHMJJP3dG53TqsgziMs\n"
        "purycJktQU/Zw4O0XuAUQd94WNhRemOQktfeRzJ/Eob0TfLMRIQgiySEdWn4bgM2\n"
        "4hvU1rOSmdOnus7Idx0t8vTV6ornXVEzgvCrXSkoUUZj75OKCN7kh2KsjWYEqNYi\n"
        "BJbkS0IBuZjKKAPmmMZa6BryNZJp5Jdb+l4yrnKtYeeeQJWnJfZHIcZHqlQgDeaC\n"
        "y9cgNf8lAgMBAAECggEABpBvhv2zeBDqHvjdKQ/M85y+u3B2vXkMqfHHRvsi0yLt\n"
        "/LoJMWdUbdfyPgap4NGLEO6ZSjaJOx76vUio/G1jTMGQ4ZothUAJvEy+5aY0LNoI\n"
        "njH4oohk2u/y819yLWN1b4bfyIogtc2svoH4KxPsjcvgzz9PPiZSxQKjlOuFfORW\n"
        "8VQiRhnE/RHt6+qCPr9Jmum1hnQq8ajuM0Br2I8GF01/oxYZYURCp56x7kGzEsyo\n"
        "qMbRERjN7MvcTBmjFa9S0DKk4gowGHLOcQUnlsjZLMU/kE7zue6zv8VEG1v6Abuo\n"
        "6ubioeLmvfzmEfBIaYgxaUC38oAM1or3t5IyeHP/yQKBgQD4F/JMKPA4Qd+QZK3T\n"
        "FdY9vrcdgIhbQSyy9eekm23cxIw/gKjqUOiB24TfZMzi6KMCiHCFE8iMrpdIE9vf\n"
        "hVA2YwonqrAybpKSFVwmdzj8UT8qvVt7DjA176jHgp9R7Hy8Y+lr4j5FYym+Me9q\n"
        "UYwM6okErhuLwK3/dplu30cG7wKBgQC24P6ptMXP9ty6dkS0E1wrAqFJlQI2z5iD\n"
        "Wal+OOVcSjGwfw5T589w7/5ocsWgxU/8HPWuC2UvQVw5hK0Q1E4D47MdZ6F+ZlJJ\n"
        "jUxWsunrGXovB0Km/Eq3QC5A4NkdFYWrK0XeecJxra0U8d6Ywb65m+7ChqUAEO3C\n"
        "6+75qD17KwKBgBJD6RHUXcM2jlgaIXYOAITxOpgQc3mMddcDJbfHvbHoQo8WUNlX\n"
        "dZbB66lqyW7XQ9EW7HnPuA8rd3XWCHUPYpVuezvqZCiCXYYlznACjQ5+iNEDue14\n"
        "YPJHn7x4kHQ+nfxcur23nXAMWfFnycGhGVeGGOpgSyTh3a2WNLul8pu/AoGACZz4\n"
        "JgmXoF/0qGSRJfoijSw9ODX6ANGWzcjHzRfGjrxjskhrg2ObFu+2qtzloJbepn0L\n"
        "ORPmRL6lz2w3ALx4QWIVx0TsS02ro6wmyCPtges77f7utQJsFwfrpoNrRkkcVqwW\n"
        "pyQ1YW5ku8YfEl6U3QLiYR1czQ0WwnlOfZcnbDMCgYEAgdDd35Ox09yi/LnlWrHD\n"
        "Yr/fEvb09bQ5mRHxSUhNkuPZys8LbEt4EO4tq3uMANsFevRlg65wMjywnT+tDKLm\n"
        "CYLKGhs5tMkWljP5hUH/MpSC3K4rta9AbMAV6EtEhwgPAxRe3e/lDmWmUs/0N9Wz\n"
        "1kIQNXimVmmxKSAXAnT1190=\n"
        "-----END PRIVATE KEY-----";

static const std::string kTestRsa2048ClientCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTE5MTIyMDA0MDYzMVoX\n"
        "DTI5MTIxNzA0MDYzMVowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFU\n"
        "gFWnYicHyYEuESFm6RAUzWOoLMIwK2rsB5u96/bq1pKm45k2vwFr606sRqNj+CYW\n"
        "BfbKOFV16FANg2YUxQegS/9YNvfEGU4UYIN1VIbifk1bfQe1g2DyoDF4JlzsfTUb\n"
        "F8UTIuFTlnRS0a20IGMQPtDvSLuGgKmXO5Uil/8f3P8JrNmj/hlBtcNH6jUPd7Gr\n"
        "P6CiVyvKnPcA6mR8dPEAr3PFU1wMWRQmz50LyKJeXHzAkoJeIc/HYTS4+i0AFSxL\n"
        "Mi/DPz7kdlCecwvOLi6HSTm60lgZcldR1zejzV4EhqrYXQGuFmLfQatVOQx6SJ3D\n"
        "geDBwSmpq3maZjEJsPsCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCASYwHQYDVR0OBBYEFKA675iWjaTKBHjmIycSyjjFT3lHMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQCcV68kxtPhSmjp3xUyPiiAD8Y0UpA0Klu/VNXTfeohM98zR3oG\n"
        "HUYohtZq6VgUm7oiMLtz1UT9dahqihsnzUU/0UBSpxsH0iRckPMLxvw32WiA9mFR\n"
        "zcpUtmJKrV5kTww8UEmF2QMbTaAmprHCEiiHO4h2QUx+SWeeikTfd28p6tt9Jq7y\n"
        "nVSa/GuIbINoPjspcsKQtfq6jAMIzlOwHPXEbwm7+KbAipM2F290kr/MYHYpEUuD\n"
        "rIpTpgsc/vR/Sf638MVKOoHUiRVMqO4ggx4GbK6H7kyehx5Hll8fJ/Ea2zkgamhZ\n"
        "yQvJDiW4pXnuzhIn5jdtxlbvJySUKr3rONf1\n"
        "-----END CERTIFICATE-----";

static const std::string kTestRsa2048ClientPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxVIBVp2InB8mB\n"
        "LhEhZukQFM1jqCzCMCtq7Aebvev26taSpuOZNr8Ba+tOrEajY/gmFgX2yjhVdehQ\n"
        "DYNmFMUHoEv/WDb3xBlOFGCDdVSG4n5NW30HtYNg8qAxeCZc7H01GxfFEyLhU5Z0\n"
        "UtGttCBjED7Q70i7hoCplzuVIpf/H9z/CazZo/4ZQbXDR+o1D3exqz+golcrypz3\n"
        "AOpkfHTxAK9zxVNcDFkUJs+dC8iiXlx8wJKCXiHPx2E0uPotABUsSzIvwz8+5HZQ\n"
        "nnMLzi4uh0k5utJYGXJXUdc3o81eBIaq2F0BrhZi30GrVTkMekidw4HgwcEpqat5\n"
        "mmYxCbD7AgMBAAECggEAGOOp4ZvNQHos07dSCzSlCK9Kxq6Pna/iIC9BwB/Pk0gR\n"
        "1uKatmIDPCFYFSJEBeHdrgbQTnvCnWgfs8C5zSWkI/ZhRFUu3ebFwHpGs5zPwODg\n"
        "Zl4tddwJtR1I07iv9cHxrvb/BpexgRvY1bncGTvbgdwBXRUAyeVOgL8ryzpgSBwG\n"
        "QoRbTWJnoehKXUcFEiuSEuksoB2TspjG9cbisP6+HxEobu9cbRu7/FyFoPCIWldD\n"
        "g+kXb2/AE/MFqzlgHSU2WAda8Z25B21iuzbtYvFuebS5wEB3Pi4inG5IfoMePUq+\n"
        "9DHA1VjtwswVLmYN5i3pbxvLEdmvFs6hppSNxRXgQQKBgQDoHkO4fd5TXVERGC0u\n"
        "K0qPmC+1UdXUGxCs2ubGNvV9tGExOCu+rqP2C7v5TJxZ6qZcMGXhPWAQNO4Vw+Ih\n"
        "V/QS174BdfBeUtoy0CYQ7hzzsmbaH06f2XAJGntT1ICJdnPw9qURJ9QoZ2oKmJV7\n"
        "K77lgYI37R4+f8P34163uU9IOwKBgQDDky2g7fJcySllb3BU8r/SHSY5dzecArps\n"
        "YsvTqstwlWiqsIzIVPUjOn+SPdcGGxlCYJH7dxUZJDQ97BJv1zHYWuCgl4SStruf\n"
        "s7AnLKDk5uEe2q86OkV6JJYkoTJpengZ1NqV3R01Bw290NNaoJoATBNdBo51TiIx\n"
        "SrkTma1uQQKBgEZXBYae/gSdPrfDb82R6OJi5/I2fmnsWb1ICK8AcJxLUTitIPSD\n"
        "z8P8Alal1Kua5BcDw5viEX5Xy95kod4g3SHopveiWdj7movTb/WpcrSW13w6CIWA\n"
        "Suc3UzAwMVN2xeO7moH8Y9pqnEPhwUq2Ev9Ro7h27rdZ2HUCPe3HBjOJAoGAJInW\n"
        "uH48DYG3ri/HuNcxZzvy7EGNriQEWEOM+Rqrr3j6eQlLBBJ7Sf2f396V0Zo2eeQ4\n"
        "4dY5ptzQtdDpEOQPd/Bijx4/snlZTFjxzB/WX22TGYSZwDMqz8sOEgHbvUEYNxtB\n"
        "S0ZoMoQC2TeuhPwESZHs/DBBZUEXukXPlg3cDQECgYEA4Zk201nNkPJEsrYflf7p\n"
        "E7BraMsN/9JpWUK7smf3LLi0xxYOztOhlXWYT79GvUZQqG5Qhuy2NUSEkTwj4zZt\n"
        "UrDTpC4VRpIyi+SIRaqREPfjIO7agQnxLpzh+WzV1qQzIFF1i7DF6fW1OmcfnjNQ\n"
        "kiVlGIjiXeVyucrc46HaW3s=\n"
        "-----END PRIVATE KEY-----";

class AdbWifiTlsConnectionTest : public testing::Test {
  protected:
    virtual void SetUp() override {
        android::base::Socketpair(SOCK_STREAM, &server_fd_, &client_fd_);
        server_ = TlsConnection::create(TlsConnection::Role::Server, kTestRsa2048ServerCert,
                                        kTestRsa2048ServerPrivKey);
        client_ = TlsConnection::create(TlsConnection::Role::Client, kTestRsa2048ClientCert,
                                        kTestRsa2048ClientPrivKey);
        ASSERT_NE(nullptr, server_);
        ASSERT_NE(nullptr, client_);
    }

    virtual void TearDown() override {
        waitForClientConnection();
        // Shutdown the SSL connection first.
        server_.reset();
        client_.reset();
    }

    void setupClientConnectionAsync(bool use_cert_verify) {
        client_thread_ = std::thread([&]() {
            client_->enableCertificateVerification(use_cert_verify);
            if (!client_->doHandshake(client_fd_.get())) {
                return;
            }
        });
    }

    void waitForClientConnection() {
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
};

TEST_F(AdbWifiTlsConnectionTest, NoCertificateVerification) {
    server_->enableCertificateVerification(false);
    setupClientConnectionAsync(false);

    // Handshake should succeed
    EXPECT_TRUE(server_->doHandshake(server_fd_.get()));
    waitForClientConnection();

    // Client write, server read
    EXPECT_TRUE(client_->writeFully(msg_));
    auto data = server_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));

    // Client read, server write
    EXPECT_TRUE(server_->writeFully(msg_));
    data = client_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));
}

TEST_F(AdbWifiTlsConnectionTest, NoTrustedCertificates) {
    server_->enableCertificateVerification(true);
    setupClientConnectionAsync(true);

    // Handshake should not succeed
    EXPECT_FALSE(server_->doHandshake(server_fd_.get()));
    waitForClientConnection();

    // Client write, server read should fail
    EXPECT_FALSE(client_->writeFully(msg_));
    auto data = server_->readFully(msg_.size());
    EXPECT_EQ(data.size(), 0);

    // Client read, server write should fail
    EXPECT_FALSE(server_->writeFully(msg_));
    data = client_->readFully(msg_.size());
    EXPECT_EQ(data.size(), 0);
}

TEST_F(AdbWifiTlsConnectionTest, AddTrustedCertificates) {
    server_->enableCertificateVerification(true);

    // Add peer certificates
    EXPECT_TRUE(client_->addTrustedCertificate(kTestRsa2048ServerCert));
    EXPECT_TRUE(server_->addTrustedCertificate(kTestRsa2048ClientCert));

    setupClientConnectionAsync(true);

    // Handshake should succeed
    EXPECT_TRUE(server_->doHandshake(server_fd_.get()));
    waitForClientConnection();

    // Client write, server read
    EXPECT_TRUE(client_->writeFully(msg_));
    auto data = server_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));

    // Client read, server write
    EXPECT_TRUE(server_->writeFully(msg_));
    data = client_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));
}

}  // namespace ssl
}  // namespace adb
