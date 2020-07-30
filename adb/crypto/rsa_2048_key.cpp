/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adb/crypto/rsa_2048_key.h"

#ifdef _WIN32
#include <lmcons.h>
#include <windows.h>
#endif  // _WIN32

#include <android-base/logging.h>
#include <android-base/utf8.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

namespace adb {
namespace crypto {

namespace {
bool HasOnlySpacesOrEmpty(std::string_view s) {
    if (s.empty()) {
        return true;
    }
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); });
}

std::optional<std::string> GetEnvironmentVariable(std::string_view var) {
    if (var.empty()) {
        return std::nullopt;
    }

#ifdef _WIN32
    constexpr size_t kMaxEnvVarSize = 32767;
    wchar_t wbuf[kMaxEnvVarSize];
    std::wstring wvar;
    if (!android::base::UTF8ToWide(var.data(), &wvar)) {
        return std::nullopt;
    }

    auto sz = ::GetEnvironmentVariableW(wvar.data(), wbuf, sizeof(wbuf));
    if (sz == 0) {
        return std::nullopt;
    }

    std::string val;
    if (!android::base::WideToUTF8(wbuf, &val)) {
        return std::nullopt;
    }

    return std::make_optional(val);
#else  // !_WIN32
    const char* val = getenv(var.data());
    if (val == nullptr) {
        return std::nullopt;
    }

    return std::make_optional(std::string(val));
#endif
}

#ifdef _WIN32
constexpr char kHostNameEnvVar[] = "COMPUTERNAME";
constexpr char kUserNameEnvVar[] = "USERNAME";
#else
constexpr char kHostNameEnvVar[] = "HOSTNAME";
constexpr char kUserNameEnvVar[] = "LOGNAME";
#endif

std::string GetHostName() {
    constexpr char defaultName[] = "nohostname";
    const auto hostName = GetEnvironmentVariable(kHostNameEnvVar);
    if (hostName && !HasOnlySpacesOrEmpty(*hostName)) {
        return *hostName;
    }

#ifdef _WIN32
    wchar_t wbuf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(wbuf);
    if (!GetComputerNameW(wbuf, &size) || size == 0) {
        return defaultName;
    }

    std::string name;
    if (!android::base::WideToUTF8(wbuf, &name) || HasOnlySpacesOrEmpty(name)) {
        return defaultName;
    }

    return name;
#else   // !_WIN32
    char buf[256];
    return (gethostname(buf, sizeof(buf)) == -1) ? defaultName : buf;
#endif  // _WIN32
}

std::string GetLoginName() {
    constexpr char defaultName[] = "nousername";
    const auto userName = GetEnvironmentVariable(kUserNameEnvVar);
    if (userName && !HasOnlySpacesOrEmpty(*userName)) {
        return *userName;
    }

#ifdef _WIN32
    wchar_t wbuf[UNLEN + 1];
    DWORD size = sizeof(wbuf);
    if (!GetUserNameW(wbuf, &size) || size == 0) {
        return defaultName;
    }

    std::string login;
    if (!android::base::WideToUTF8(wbuf, &login) || HasOnlySpacesOrEmpty(login)) {
        return defaultName;
    }

    return login;
#else   // !_WIN32
    const char* login = getlogin();
    return login ? login : defaultName;
#endif  // _WIN32
}

std::string GetUserInfo() {
    return GetLoginName() + "@" + GetHostName();
}
}  // namespace

bool CalculatePublicKey(std::string* out, RSA* private_key) {
    uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    if (!android_pubkey_encode(private_key, binary_key_data, sizeof(binary_key_data))) {
        LOG(ERROR) << "Failed to convert to public key";
        return false;
    }

    size_t expected_length;
    if (!EVP_EncodedLength(&expected_length, sizeof(binary_key_data))) {
        LOG(ERROR) << "Public key too large to base64 encode";
        return false;
    }

    out->resize(expected_length);
    size_t actual_length = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(out->data()), binary_key_data,
                                           sizeof(binary_key_data));
    out->resize(actual_length);
    out->append(" ");
    out->append(GetUserInfo());
    return true;
}

std::optional<Key> CreateRSA2048Key() {
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    bssl::UniquePtr<BIGNUM> exponent(BN_new());
    bssl::UniquePtr<RSA> rsa(RSA_new());
    if (!pkey || !exponent || !rsa) {
        LOG(ERROR) << "Failed to allocate key";
        return std::nullopt;
    }

    BN_set_word(exponent.get(), RSA_F4);
    RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr);
    EVP_PKEY_set1_RSA(pkey.get(), rsa.get());

    return std::optional<Key>{Key(std::move(pkey), adb::proto::KeyType::RSA_2048)};
}

}  // namespace crypto
}  // namespace adb
