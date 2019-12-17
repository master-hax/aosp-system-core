/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "adb/ssl/adb_ca_list.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

//#include <openssl/asn1.h>
#include <android-base/logging.h>
#include <openssl/ssl.h>

namespace adb {
namespace ssl {

namespace {

// CA issuer identifier to distinguished embedded keys
static constexpr int kAdbKeyIdentifierNid = NID_organizationName;
static constexpr char kAdbKeyIdentifierSN[] = SN_organizationName;
static constexpr char kAdbKeyIdentifierValue[] = "AdbKey";

// Where we store the actual data
static constexpr int kAdbKeyValueNid = NID_commonName;
static constexpr char kAdbKeyValueSN[] = SN_commonName;
static constexpr size_t kAdbKeyValueMaxSize = ub_common_name;

// In case we want to change the way we parse the CA issuer
// in future version.
// static constexpr int kAdbKeyVersionNid = NID_countryName;
static constexpr char kAdbKeyVersionSN[] = SN_countryName;
static constexpr char kAdbKeyVersionAttrValue[] = "00";

struct CAIssuerField {
    const char* field;
    const char* value;
};  // CAIssuerField

static std::vector<CAIssuerField> kCAIssuerName{
        {kAdbKeyVersionSN, kAdbKeyVersionAttrValue},
        {kAdbKeyIdentifierSN, kAdbKeyIdentifierValue},
};

// The numeric identifier (NID) used to determine whether the CA issuer is
// actually a known adb key masquerading as a CA issuer. Use in
// X509_NAME_get_text_by_NID() and compare against GetAdbKeyAttrText() to
// determine.
int GetAdbKeyAttrNid() {
    return kAdbKeyIdentifierNid;
}

// Returns the text for GetAdbKeyAttrNid() that is used to determine if the CA
// issuer is an adb known key. Compare against the text returned by
// X509_NAME_get_text_by_NID(..., GetAdbKeyAttrNid(), ...).
std::string GetAdbKeyAttrText() {
    return kAdbKeyIdentifierValue;
}

}  // namespace

// Returns the max length the attribute value can be. This depends on which
// attribute we are using internally (see RFC2459).
size_t GetAdbKeyMaxSize() {
    return kAdbKeyValueMaxSize;
}

// Takes an encoded public key and generates a X509_NAME that can be used in
// TlsConnection::SetClientCAList(), to allow the client to figure out which of
// its keys it should try to use in the TLS handshake. Note: the key length must
// be within GetAdbKeyMaxSize().
bssl::UniquePtr<X509_NAME> CreateCAIssuerFromEncodedKey(std::string_view key) {
    // "C=00;O=AdbKey;CN=<key>;"
    CHECK(!key.empty());
    CHECK_LE(key.size(), GetAdbKeyMaxSize());

    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    for (auto& attr : kCAIssuerName) {
        CHECK(X509_NAME_add_entry_by_txt(name.get(), attr.field, MBSTRING_ASC,
                                         reinterpret_cast<const uint8_t*>(attr.value), -1, -1, 0));
    }

    CHECK(X509_NAME_add_entry_by_txt(name.get(), kAdbKeyValueSN, MBSTRING_ASC,
                                     reinterpret_cast<const uint8_t*>(key.data()), -1, -1, 0));
    return name;
}

// Parses a CA issuer and returns the encoded key, if any.
std::string ParseEncodedKeyFromCAIssuer(X509_NAME* issuer) {
    CHECK(issuer);
    std::string out_buf(128, 0);

    // Try to determine if this X509_NAME has the key attribute
    int len = X509_NAME_get_text_by_NID(issuer, GetAdbKeyAttrNid(), out_buf.data(), out_buf.size());
    if (len <= 0) {
        return "";
    }
    out_buf.resize(len);
    if (out_buf != GetAdbKeyAttrText()) {
        return "";
    }

    // Extract the key
    out_buf.resize(GetAdbKeyMaxSize() + 1);
    len = X509_NAME_get_text_by_NID(issuer, kAdbKeyValueNid, out_buf.data(), out_buf.size());
    if (len <= 0) {
        return "";
    }
    out_buf.resize(len);

    return out_buf;
}

std::string SHA256BitsToHexString(std::string_view sha256) {
    CHECK_EQ(sha256.size(), static_cast<size_t>(SHA256_DIGEST_LENGTH));
    std::stringstream ss;
    // Convert to hex-string representation
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex
           << (0x00FF & sha256[i]);
    }
    return ss.str();
}

std::string SHA256HexStringToBits(std::string_view sha256_str) {
    if (sha256_str.size() != SHA256_DIGEST_LENGTH * 2) {
        return "";
    }

    std::string result;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        auto bytestr = std::string(sha256_str.substr(i * 2, 2));
        if (!isxdigit(bytestr[0]) || !isxdigit(bytestr[1])) {
            LOG(ERROR) << "SHA256 string has invalid non-hex chars";
            return "";
        }
        result += static_cast<char>(std::stol(bytestr, nullptr, 16));
    }
    return result;
}

}  // namespace ssl
}  // namespace adb
