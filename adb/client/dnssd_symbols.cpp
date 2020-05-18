/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define TRACE_TAG MDNS

#include "client/dnssd_symbols.h"

#if defined(__linux__)
#include <arpa/inet.h>
#include <dlfcn.h>
#endif

#include <optional>
#include <vector>

#include <android-base/endian.h>
#include <android-base/logging.h>

#include "adb_trace.h"

namespace mdns {

namespace {
std::optional<AdbDnssdFuncs> sDnsSdFuncs;

#if defined(__linux__)
struct GetAddrCallback {
    DNSServiceGetAddrInfoReply cb;
    void* context;
    explicit GetAddrCallback(DNSServiceGetAddrInfoReply cb, void* context)
        : cb(cb), context(context) {}
    GetAddrCallback(GetAddrCallback& copy) = delete;
    GetAddrCallback& operator=(GetAddrCallback& copy) = delete;
    GetAddrCallback(GetAddrCallback&& move) = default;
    GetAddrCallback& operator=(GetAddrCallback&& move) = default;
};

void DNSSD_API query_record_reply(DNSServiceRef sdRef, DNSServiceFlags flags,
                                  uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                                  const char* fullname, uint16_t rrtype, uint16_t rrclass,
                                  uint16_t rdlen, const void* rdata, uint32_t ttl, void* context) {
    std::unique_ptr<GetAddrCallback> userdata(reinterpret_cast<GetAddrCallback*>(context));
    if (errorCode != kDNSServiceErr_NoError || rdlen == 0) {
        LOG(WARNING) << "Failure in DNSServiceQueryRecord err=" << errorCode;
        userdata->cb(sdRef, flags, interfaceIndex, errorCode, fullname, nullptr, ttl,
                     userdata->context);
        return;
    }

    switch (rrtype) {
        case kDNSServiceType_A: {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            memcpy(&addr.sin_addr, rdata, rdlen);
            userdata->cb(sdRef, flags, interfaceIndex, errorCode, fullname,
                         reinterpret_cast<sockaddr*>(&addr), ttl, userdata->context);
        } break;
        default:
            break;
    }
}

// This function implements DNSServiceGetAddrInfo when using the libavahi-compat library, since it
// doesn't exist.
DNSServiceErrorType DNSSD_API
avahi_DNSServiceGetAddrInfo(DNSServiceRef* sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                            DNSServiceProtocol protocol, const char* hostname,
                            DNSServiceGetAddrInfoReply callback, void* context) {
    // No support for ipv6 yet.
    CHECK(!(protocol & kDNSServiceProtocol_IPv6));
    CHECK(protocol & kDNSServiceProtocol_IPv4);

    // Query for the A record (AAAA record for ipv6 addresses)
    std::unique_ptr<GetAddrCallback> userdata(new GetAddrCallback(callback, context));
    auto err = sDnsSdFuncs->DNSServiceQueryRecord(sdRef, flags, interfaceIndex, hostname,
                                                  kDNSServiceType_A, kDNSServiceClass_IN,
                                                  query_record_reply, userdata.get());
    if (err == kDNSServiceErr_NoError) {
        userdata.release();
    }
    return err;
}

DNSServiceErrorType DNSSD_API avahi_DNSServiceGetProperty(const char* property, void* result,
                                                          uint32_t* size) {
    // TODO: Check if avahi-daemon is running
    LOG(WARNING) << __func__ << ": Using avahi-compat library";
    return kDNSServiceErr_Unsupported;
}
#endif  // __linux__

void adb_dnssd_funcs_default(AdbDnssdFuncs& f) {
#define ADB_DNSSD_FUNC(name) f.name = name
    ADB_DNSSD_FUNC(DNSServiceRefSockFD);
    ADB_DNSSD_FUNC(DNSServiceProcessResult);
    ADB_DNSSD_FUNC(DNSServiceRefDeallocate);
    ADB_DNSSD_FUNC(DNSServiceResolve);
    ADB_DNSSD_FUNC(DNSServiceBrowse);
    ADB_DNSSD_FUNC(DNSServiceQueryRecord);
    ADB_DNSSD_FUNC(DNSServiceGetAddrInfo);
    ADB_DNSSD_FUNC(DNSServiceGetProperty);
#undef ADB_DNSSD_FUNC
}
}  // namespace

const AdbDnssdFuncs* get_adb_dnssd_funcs() {
    if (sDnsSdFuncs.has_value()) {
        return &*sDnsSdFuncs;
    }

    sDnsSdFuncs = {};
#if defined(__linux__)
    LOG(INFO) << "Attempting to use avahi-compat library (libdns_sd.so)";
    void* avahi_dnssd_handle = dlopen("libdns_sd.so", RTLD_NOW);
    if (avahi_dnssd_handle != nullptr) {
        LOG(INFO) << "Found libdns_sd.so. Attempting to load symbols";
#define ADB_DNSSD_FUNC(name)                                                                   \
    sDnsSdFuncs->name =                                                                        \
            reinterpret_cast<decltype(AdbDnssdFuncs::name)>(dlsym(avahi_dnssd_handle, #name)); \
    if (sDnsSdFuncs->name == nullptr) {                                                        \
        LOG(WARNING) << "Couldn't find " << #name << ". Falling back to libmdnssd APIs.";      \
        adb_dnssd_funcs_default(*sDnsSdFuncs);                                                 \
        return &*sDnsSdFuncs;                                                                  \
    }
        ADB_DNSSD_FUNC(DNSServiceRefSockFD)
        ADB_DNSSD_FUNC(DNSServiceProcessResult)
        ADB_DNSSD_FUNC(DNSServiceRefDeallocate)
        ADB_DNSSD_FUNC(DNSServiceResolve)
        ADB_DNSSD_FUNC(DNSServiceBrowse)
        ADB_DNSSD_FUNC(DNSServiceQueryRecord)
        sDnsSdFuncs->DNSServiceGetAddrInfo = avahi_DNSServiceGetAddrInfo;
        sDnsSdFuncs->DNSServiceGetProperty = avahi_DNSServiceGetProperty;
#undef ADB_DNSSD_FUNC
    } else {
        LOG(INFO) << "Avahi-compat library not found. Defaulting to libmdnssd APIs";
        adb_dnssd_funcs_default(*sDnsSdFuncs);
    }
#else   // !__linux__
    LOG(INFO) << "Using libmdnssd APIs";
    adb_dnssd_funcs_default(*sDnsSdFuncs);
#endif  // __linux__
    return &*sDnsSdFuncs;
}

}  // namespace mdns
