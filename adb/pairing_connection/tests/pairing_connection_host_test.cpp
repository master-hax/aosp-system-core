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

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <adb/pairing/pairing_connection.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "../internal/constants.h"
#include "sysdeps.h"

using namespace std::chrono_literals;
using android::base::unique_fd;

namespace adb {
namespace pairing {

// Test X.509 certificates (RSA 2048)
[[clang::no_destroy]] const std::string kTestRsa2048ServerCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyMTIyMjU1NVoX\n"
        "DTMwMDExODIyMjU1NVowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8E\n"
        "2Ck9TfuKlz7wqWdMfknjZ1luFDp2IHxAUZzh/F6jeI2dOFGAjpeloSnGOE86FIaT\n"
        "d1EvpyTh7nBwbrLZAA6XFZTo7Bl6BdNOQdqb2d2+cLEN0inFxqUIycevRtohUE1Y\n"
        "FHM9fg442X1jOTWXjDZWeiqFWo95paAPhzm6pWqfJK1+YKfT1LsWZpYqJGGQE5pi\n"
        "C3qOBYYgFpoXMxTYJNoZo3uOYEdM6upc8/vh15nMgIxX/ymJxEY5BHPpZPPWjXLg\n"
        "BfzVaV9fUfv0JT4HQ4t2WvxC3cD/UsjWp2a6p454uUp2ENrANa+jRdRJepepg9D2\n"
        "DKsx9L8zjc5Obqexrt0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFDFW+8GTErwoZN5Uu9KyY4QdGYKpMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQBCDEn6SHXGlq5TU7J8cg1kRPd9bsJW+0hDuKSq0REXDkl0PcBf\n"
        "fy282Agg9enKPPKmnpeQjM1dmnxdM8tT8LIUbMl779i3fn6v9HJVB+yG4gmRFThW\n"
        "c+AGlBnrIT820cX/gU3h3R3FTahfsq+1rrSJkEgHyuC0HYeRyveSckBdaEOLvx0S\n"
        "toun+32JJl5hWydpUUZhE9Mbb3KHBRM2YYZZU9JeJ08Apjl+3lRUeMAUwI5fkAAu\n"
        "z/1SqnuGL96bd8P5ixdkA1+rF8FPhodGcq9mQOuUGP9g5HOXjaNoJYvwVRUdLeGh\n"
        "cP/ReOTwQIzM1K5a83p8cX8AGGYmM7dQp7ec\n"
        "-----END CERTIFICATE-----\n";

[[clang::no_destroy]] const std::string kTestRsa2048ServerPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCvBNgpPU37ipc+\n"
        "8KlnTH5J42dZbhQ6diB8QFGc4fxeo3iNnThRgI6XpaEpxjhPOhSGk3dRL6ck4e5w\n"
        "cG6y2QAOlxWU6OwZegXTTkHam9ndvnCxDdIpxcalCMnHr0baIVBNWBRzPX4OONl9\n"
        "Yzk1l4w2VnoqhVqPeaWgD4c5uqVqnyStfmCn09S7FmaWKiRhkBOaYgt6jgWGIBaa\n"
        "FzMU2CTaGaN7jmBHTOrqXPP74deZzICMV/8picRGOQRz6WTz1o1y4AX81WlfX1H7\n"
        "9CU+B0OLdlr8Qt3A/1LI1qdmuqeOeLlKdhDawDWvo0XUSXqXqYPQ9gyrMfS/M43O\n"
        "Tm6nsa7dAgMBAAECggEAFCS2bPdUKIgjbzLgtHW+hT+J2hD20rcHdyAp+dNH/2vI\n"
        "yLfDJHJA4chGMRondKA704oDw2bSJxxlG9t83326lB35yxPhye7cM8fqgWrK8PVl\n"
        "tU22FhO1ZgeJvb9OeXWNxKZyDW9oOOJ8eazNXVMuEo+dFj7B6l3MXQyHJPL2mJDm\n"
        "u9ofFLdypX+gJncVO0oW0FNJnEUn2MMwHDNlo7gc4WdQuidPkuZItKRGcB8TTGF3\n"
        "Ka1/2taYdTQ4Aq//Z84LlFvE0zD3T4c8LwYYzOzD4gGGTXvft7vSHzIun1S8YLRS\n"
        "dEKXdVjtaFhgH3uUe4j+1b/vMvSHeoGBNX/G88GD+wKBgQDWUYVlMVqc9HD2IeYi\n"
        "EfBcNwAJFJkh51yAl5QbUBgFYgFJVkkS/EDxEGFPvEmI3/pAeQFHFY13BI466EPs\n"
        "o8Z8UUwWDp+Z1MFHHKQKnFakbsZbZlbqjJ9VJsqpezbpWhMHTOmcG0dmE7rf0lyM\n"
        "eQv9slBB8qp2NEUs5Of7f2C2bwKBgQDRDq4nUuMQF1hbjM05tGKSIwkobmGsLspv\n"
        "TMhkM7fq4RpbFHmbNgsFqMhcqYZ8gY6/scv5KCuAZ4yHUkbqwf5h+QCwrJ4uJeUJ\n"
        "ZgJfHus2mmcNSo8FwSkNoojIQtzcbJav7bs2K9VTuertk/i7IJLApU4FOZZ5pghN\n"
        "EXu0CZF1cwKBgDWFGhjRIF29tU/h20R60llU6s9Zs3wB+NmsALJpZ/ZAKS4VPB5f\n"
        "nCAXBRYSYRKrTCU5kpYbzb4BBzuysPOxWmnFK4j+keCqfrGxd02nCQP7HdHJVr8v\n"
        "6sIq88UrHeVcNxBFprjzHvtgxfQK5k22FMZ/9wbhAKyQFQ5HA5+MiaxFAoGAIcZZ\n"
        "ZIkDninnYIMS9OursShv5lRO+15j3i9tgKLKZ+wOMgDQ1L6acUOfezj4PU1BHr8+\n"
        "0PYocQpJreMhCfRlgLaV4fVBaPs+UZJld7CrF5tCYudUy/01ALrtlk0XGZWBktK5\n"
        "mDrksC4tQkzRtonAq9cJD9cJ9IVaefkFH0UcdvkCgYBpZj50VLeGhnHHBnkJRlV1\n"
        "fV+/P6PAq6RtqjA6O9Qdaoj5V3w2d63aQcQXQLJjH2BBmtCIy47r04rFvZpbCxP7\n"
        "NH/OnK9NHpk2ucRTe8TAnVbvF/TZzPJoIxAO/D3OWaW6df4R8en8u6GYzWFglAyT\n"
        "sydGT8yfWD1FYUWgfrVRbg==\n"
        "-----END PRIVATE KEY-----\n";

[[clang::no_destroy]] const std::string kTestRsa2048ClientCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyMTIyMjU1NloX\n"
        "DTMwMDExODIyMjU1NlowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI3a\n"
        "EXh1S5FTbet7JVONswffRPaekdIK53cb8SnAbSO9X5OLA4zGwdkrBvDTsd96SKrp\n"
        "JxmoNOE1DhbZh05KPlWAPkGKacjGWaz+S7biDOL0I6aaLbTlU/il1Ub9olPSBVUx\n"
        "0nhdtEFgIOzddnP6/1KmyIIeRxS5lTKeg4avqUkZNXkz/wL1dHBFL7FNFf0SCcbo\n"
        "tsub/deFbjZ27LTDN+SIBgFttTNqC5NTvoBAoMdyCOAgNYwaHO+fKiK3edfJieaw\n"
        "7HD8qqmQxcpCtRlA8CUPj7GfR+WHiCJmlevhnkFXCo56R1BS0F4wuD4KPdSWt8gc\n"
        "27ejH/9/z2cKo/6SLJMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFO/Mr5ygqqpyU/EHM9v7RDvcqaOkMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQAH33KMouzF2DYbjg90KDrDQr4rq3WfNb6P743knxdUFuvb+40U\n"
        "QjC2OJZHkSexH7wfG/y6ic7vfCfF4clNs3QvU1lEjOZC57St8Fk7mdNdsWLwxEMD\n"
        "uePFz0dvclSxNUHyCVMqNxddzQYzxiDWQRmXWrUBliMduQqEQelcxW2yDtg8bj+s\n"
        "aMpR1ra9scaD4jzIZIIxLoOS9zBMuNRbgP217sZrniyGMhzoI1pZ/izN4oXpyH7O\n"
        "THuaCzzRT3ph2f8EgmHSodz3ttgSf2DHzi/Ez1xUkk7NOlgNtmsxEdrM47+cC5ae\n"
        "fIf2V+1o1JW8J7D11RmRbNPh3vfisueB4f88\n"
        "-----END CERTIFICATE-----\n";

[[clang::no_destroy]] const std::string kTestRsa2048ClientPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCN2hF4dUuRU23r\n"
        "eyVTjbMH30T2npHSCud3G/EpwG0jvV+TiwOMxsHZKwbw07Hfekiq6ScZqDThNQ4W\n"
        "2YdOSj5VgD5BimnIxlms/ku24gzi9COmmi205VP4pdVG/aJT0gVVMdJ4XbRBYCDs\n"
        "3XZz+v9SpsiCHkcUuZUynoOGr6lJGTV5M/8C9XRwRS+xTRX9EgnG6LbLm/3XhW42\n"
        "duy0wzfkiAYBbbUzaguTU76AQKDHcgjgIDWMGhzvnyoit3nXyYnmsOxw/KqpkMXK\n"
        "QrUZQPAlD4+xn0flh4giZpXr4Z5BVwqOekdQUtBeMLg+Cj3UlrfIHNu3ox//f89n\n"
        "CqP+kiyTAgMBAAECggEAAa64eP6ggCob1P3c73oayYPIbvRqiQdAFOrr7Vwu7zbr\n"
        "z0rde+n6RU0mrpc+4NuzyPMtrOGQiatLbidJB5Cx3z8U00ovqbCl7PtcgorOhFKe\n"
        "VEzihebCcYyQqbWQcKtpDMhOgBxRwFoXieJb6VGXfa96FAZalCWvXgOrTl7/BF2X\n"
        "qMqIm9nJi+yS5tIO8VdOsOmrMWRH/b/ENUcef4WpLoxTXr0EEgyKWraeZ/hhXo1e\n"
        "z29dZKqdr9wMsq11NPsRddwS94jnDkXTo+EQyWVTfB7gb6yyp07s8jysaDb21tVv\n"
        "UXB9MRhDV1mOv0ncXfXZ4/+4A2UahmZaLDAVLaat4QKBgQDAVRredhGRGl2Nkic3\n"
        "KvZCAfyxug788CgasBdEiouz19iCCwcgMIDwnq0s3/WM7h/laCamT2x38riYDnpq\n"
        "rkYMfuVtU9CjEL9pTrdfwbIRhTwYNqADaPz2mXwQUhRXutE5TIdgxxC/a+ZTh0qN\n"
        "S+vhTj/4hf0IZhMh5Nqj7IPExQKBgQC8zxEzhmSGjys0GuE6Wl6Doo2TpiR6vwvi\n"
        "xPLU9lmIz5eca/Rd/eERioFQqeoIWDLzx52DXuz6rUoQhbJWz9hP3yqCwXD+pbNP\n"
        "oDJqDDbCC4IMYEb0IK/PEPH+gIpnTjoFcW+ecKDFG7W5Lt05J8WsJsfOaJvMrOU+\n"
        "dLXq3IgxdwKBgQC5RAFq0v6e8G+3hFaEHL0z3igkpt3zJf7rnj37hx2FMmDa+3Z0\n"
        "umQp5B9af61PgL12xLmeMBmC/Wp1BlVDV/Yf6Uhk5Hyv5t0KuomHEtTNbbLyfAPs\n"
        "5P/vJu/L5NS1oT4S3LX3MineyjgGs+bLbpub3z1dzutrYLADUSiPCK/xJQKBgBQt\n"
        "nQ0Ao+Wtj1R2OvPdjJRM3wyUiPmFSWPm4HzaBx+T8AQLlYYmB9O0FbXlMtnJc0iS\n"
        "YMcVcgYoVu4FG9YjSF7g3s4yljzgwJUV7c1fmMqMKE3iTDLy+1cJ3JLycdgwiArk\n"
        "4KTyLHxkRbuQwpvFIF8RlfD9RQlOwQE3v+llwDhpAoGBAL6XG6Rp6mBoD2Ds5c9R\n"
        "943yYgSUes3ji1SI9zFqeJtj8Ml/enuK1xu+8E/BxB0//+vgZsH6i3i8GFwygKey\n"
        "CGJF8CbiHc3EJc3NQIIRXcni/CGacf0HwC6m+PGFDBIpA4H2iDpVvCSofxttQiq0\n"
        "/Z7HXmXUvZHVyYi/QzX2Gahj\n"
        "-----END PRIVATE KEY-----\n";

struct ConnectionDeleter {
    void operator()(PairingConnectionCtx* p) { pairing_connection_destroy(p); }
};
using ConnectionPtr = std::unique_ptr<PairingConnectionCtx, ConnectionDeleter>;

struct ResultWaiter {
    std::mutex mutex_;
    std::condition_variable cv_;
    std::optional<bool> is_valid_;
    PeerInfo peer_info_;

    static void ResultCallback(const PeerInfo* peer_info, int fd, void* opaque) {
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
    virtual void SetUp() override {}

    virtual void TearDown() override {}

    void InitPairing(const std::vector<uint8_t>& server_pswd,
                     const std::vector<uint8_t>& client_pswd) {
        server_ = CreateServer(server_pswd);
        client_ = CreateClient(client_pswd);
    }

    static ConnectionPtr CreateServer(const std::vector<uint8_t>& pswd) {
        return CreateConnectionPtr(true, pswd, &server_info_, kTestRsa2048ServerCert,
                                   kTestRsa2048ServerPrivKey);
    }

    static ConnectionPtr CreateClient(const std::vector<uint8_t>& pswd) {
        return CreateConnectionPtr(false, pswd, &client_info_, kTestRsa2048ClientCert,
                                   kTestRsa2048ClientPrivKey);
    }

    static ConnectionPtr CreateConnectionPtr(bool is_server, const std::vector<uint8_t>& pswd,
                                             const PeerInfo* peer_info, const std::string_view cert,
                                             const std::string_view priv_key) {
        auto func = is_server ? pairing_connection_server_new : pairing_connection_client_new;
        return ConnectionPtr(func(
                pswd.data(), pswd.size(), peer_info, reinterpret_cast<const uint8_t*>(cert.data()),
                cert.size(), reinterpret_cast<const uint8_t*>(priv_key.data()), priv_key.size()));
    }

    // Returns the port listening on
    static int CreateLoopbackServer(unique_fd& fd) {
        std::string err;
        fd.reset(network_loopback_server(0, SOCK_STREAM, &err, true));
        EXPECT_GT(fd.get(), 0);
        close_on_exec(fd.get());
        disable_tcp_nagle(fd.get());
        int port = socket_get_local_port(fd.get());
        return port;
    }

    static void CreateLoopbackClient(unique_fd& fd, int port) {
        std::string err;
        fd.reset(network_loopback_client(port, SOCK_STREAM, &err));
        ASSERT_GE(fd.get(), 0);
        close_on_exec(fd.get());
        disable_tcp_nagle(fd.get());
    }

    static constexpr PeerInfo server_info_ = {
            .type = ADB_DEVICE_GUID,
            .data = "my_server_info",
    };
    static constexpr PeerInfo client_info_ = {
            .type = ADB_RSA_PUB_KEY,
            .data = "my_client_info",
    };

    unique_fd server_fd_;
    unique_fd client_fd_;
    ConnectionPtr server_;
    ConnectionPtr client_;
};

TEST_F(AdbPairingConnectionTest, SmokeValidPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    InitPairing(pswd, pswd);

    // Start the server
    int port = CreateLoopbackServer(server_fd_);
    ASSERT_GT(port, 0);
    ASSERT_LE(port, 65535);

    std::thread server_thread([&] {
        unique_fd new_fd(adb_socket_accept(server_fd_, nullptr, nullptr));
        ASSERT_GE(new_fd.get(), 0);

        ResultWaiter server_waiter;
        std::unique_lock<std::mutex> lock(server_waiter.mutex_);
        ASSERT_TRUE(pairing_connection_start(server_.get(), new_fd.release(),
                                             server_waiter.ResultCallback, &server_waiter));
        server_waiter.cv_.wait(lock, [&]() { return server_waiter.is_valid_.has_value(); });

        ASSERT_TRUE(*(server_waiter.is_valid_));
        ASSERT_EQ(strlen(reinterpret_cast<const char*>(server_waiter.peer_info_.data)),
                  strlen(reinterpret_cast<const char*>(client_info_.data)));
        EXPECT_EQ(
                memcmp(server_waiter.peer_info_.data, client_info_.data, sizeof(client_info_.data)),
                0);
    });

    // Start the client
    std::thread client_thread([&] {
        CreateLoopbackClient(client_fd_, port);
        ResultWaiter client_waiter;
        std::unique_lock<std::mutex> lock(client_waiter.mutex_);
        ASSERT_TRUE(pairing_connection_start(client_.get(), client_fd_.release(),
                                             client_waiter.ResultCallback, &client_waiter));
        client_waiter.cv_.wait(lock, [&]() { return client_waiter.is_valid_.has_value(); });

        ASSERT_TRUE(*(client_waiter.is_valid_));
        ASSERT_EQ(strlen(reinterpret_cast<const char*>(client_waiter.peer_info_.data)),
                  strlen(reinterpret_cast<const char*>(server_info_.data)));
        EXPECT_EQ(
                memcmp(client_waiter.peer_info_.data, server_info_.data, sizeof(server_info_.data)),
                0);
    });

    server_thread.join();
    client_thread.join();
}

}  // namespace pairing
}  // namespace adb
