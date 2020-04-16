/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _ADB_MDNS_H_
#define _ADB_MDNS_H_

#include <android-base/macros.h>

// According to RFC 6763 (https://tools.ietf.org/html/rfc6763#section-7.2), the service name has a
// length limit of 15 bytes, excluding the leading underscore. So including the "._tcp", the max
// size should be 21 bytes (22 bytes if we include the dot at the beginning of the name).
//
// Furthermore, service names can only contain letters, digits, and hyphens, must begin and end with
// a letter or digit, must not contain consecutive hyphens, and must contain at least one letter.
#define ADB_SERVICE_TYPE_MAX_LENGTH 21

const char kADBServiceType[] = "_adb._tcp";
static_assert(sizeof(kADBServiceType) - 1 <= ADB_SERVICE_TYPE_MAX_LENGTH, "Service name too large");
const char kADBSecurePairingServiceType[] = "_adb-tls-pairing._tcp";
static_assert(sizeof(kADBSecurePairingServiceType) - 1 <= ADB_SERVICE_TYPE_MAX_LENGTH,
              "Service name too large");
const char kADBSecureConnectServiceType[] = "_adb-tls-connect._tcp";
static_assert(sizeof(kADBSecureConnectServiceType) - 1 <= ADB_SERVICE_TYPE_MAX_LENGTH,
              "Service name too large");

const int kADBTransportServiceRefIndex = 0;
const int kADBSecurePairingServiceRefIndex = 1;
const int kADBSecureConnectServiceRefIndex = 2;

// Each ADB Secure service advertises with a TXT record indicating the version
// using a key/value pair per RFC 6763 (https://tools.ietf.org/html/rfc6763).
//
// The first key/value pair is always the version of the protocol.
// There may be more key/value pairs added after.
//
// The version is purposely represented as the single letter "v" due to the
// need to minimize DNS traffic. The version starts at 1.  With each breaking
// protocol change, the version is incremented by 1.
//
// Newer adb clients/daemons need to recognize and either reject
// or be backward-compatible with older verseions if there is a mismatch.
//
// Relevant sections:
//
// """
// 6.4.  Rules for Keys in DNS-SD Key/Value Pairs
//
// The key MUST be at least one character.  DNS-SD TXT record strings
// beginning with an '=' character (i.e., the key is missing) MUST be
// silently ignored.
//
// ...
//
// 6.5.  Rules for Values in DNS-SD Key/Value Pairs
//
// If there is an '=' in a DNS-SD TXT record string, then everything
// after the first '=' to the end of the string is the value.  The value
// can contain any eight-bit values including '='.
// """

#define ADB_SECURE_SERVICE_VERSION_TXT_RECORD(ver) ("v=" #ver)

// Client/service versions are initially defined to be matching,
// but may go out of sync as different clients and services
// try to talk to each other.
#define ADB_SECURE_SERVICE_VERSION 1
#define ADB_SECURE_CLIENT_VERSION ADB_SECURE_SERVICE_VERSION

const char* kADBSecurePairingServiceTxtRecord =
        ADB_SECURE_SERVICE_VERSION_TXT_RECORD(ADB_SECURE_SERVICE_VERSION);
const char* kADBSecureConnectServiceTxtRecord =
        ADB_SECURE_SERVICE_VERSION_TXT_RECORD(ADB_SECURE_SERVICE_VERSION);

const char* kADBDNSServices[] = {
        kADBServiceType,
        kADBSecurePairingServiceType,
        kADBSecureConnectServiceType,
};

const char* kADBDNSServiceTxtRecords[] = {
        nullptr,
        kADBSecurePairingServiceTxtRecord,
        kADBSecureConnectServiceTxtRecord,
};

const int kNumADBDNSServices = arraysize(kADBDNSServices);

#endif
