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

#include "client/dnssd_symbols.h"

#if defined(__linux__)
#include <dlfcn.h>
#endif

#include <optional>

#include <android-base/logging.h>

namespace mdns {

namespace {
std::optional<AdbDnssdFuncs> sLibmdnssdFuncs;

void adb_dnssd_funcs_default(AdbDnssdFuncs& f) {
#define ADB_DNSSD_FUNC(name) f.name = name
    ADB_DNSSD_FUNC(DNSServiceRefSockFD);
    ADB_DNSSD_FUNC(DNSServiceProcessResult);
    ADB_DNSSD_FUNC(DNSServiceRefDeallocate);
    ADB_DNSSD_FUNC(DNSServiceResolve);
    ADB_DNSSD_FUNC(DNSServiceBrowse);
    ADB_DNSSD_FUNC(DNSServiceGetAddrInfo);
    ADB_DNSSD_FUNC(DNSServiceGetProperty);
#undef ADB_DNSSD_FUNC
}

#if defined(__linux__)
DNSServiceErrorType avahi_DNSServiceGetAddrInfo(DNSServiceRef* sdRef, DNSServiceFlags flags,
                                                uint32_t interfaceIndex,
                                                DNSServiceProtocol protocol, const char* hostname,
                                                DNSServiceGetAddrInfoReply callBack,
                                                void* context) {
    LOG(WARNING) << __func__ << ": NOT IMPLEMENTED";
    return kDNSServiceErr_Unsupported;
}

DNSServiceErrorType avahi_DNSServiceGetProperty(const char* property, void* result,
                                                uint32_t* size) {
    LOG(WARNING) << __func__ << ": NOT IMPLEMENTED";
    return kDNSServiceErr_Unsupported;
}
#endif  // __linux__
}  // namespace

const AdbDnssdFuncs* get_adb_dnssd_funcs() {
    if (sLibmdnssdFuncs.has_value()) {
        return &*sLibmdnssdFuncs;
    }

    sLibmdnssdFuncs = {};
#if defined(__linux__)
    LOG(INFO) << "Attempting to use avahi-compat library (libdns_sd.so)";
    void* avahi_dnssd_handle = dlopen("libdns_sd.so", RTLD_NOW);
    if (avahi_dnssd_handle != nullptr) {
        LOG(INFO) << "Found libdns_sd.so. Attempting to load symbols";
#define ADB_DNSSD_FUNC(name)                                                                   \
    sLibmdnssdFuncs->name =                                                                    \
            reinterpret_cast<decltype(AdbDnssdFuncs::name)>(dlsym(avahi_dnssd_handle, #name)); \
    if (sLibmdnssdFuncs->name == nullptr) {                                                    \
        LOG(WARNING) << "Couldn't find " << #name << ". Falling back to libmdnssd APIs.";      \
        adb_dnssd_funcs_default(*sLibmdnssdFuncs);                                             \
        return &*sLibmdnssdFuncs;                                                              \
    }
        ADB_DNSSD_FUNC(DNSServiceRefSockFD)
        ADB_DNSSD_FUNC(DNSServiceProcessResult)
        ADB_DNSSD_FUNC(DNSServiceRefDeallocate)
        ADB_DNSSD_FUNC(DNSServiceResolve)
        ADB_DNSSD_FUNC(DNSServiceBrowse)
        sLibmdnssdFuncs->DNSServiceGetAddrInfo = avahi_DNSServiceGetAddrInfo;
        sLibmdnssdFuncs->DNSServiceGetProperty = avahi_DNSServiceGetProperty;
#undef ADB_DNSSD_FUNC
    } else {
        LOG(INFO) << "Avahi-compat library not found. Defaulting to libmdnssd APIs";
        adb_dnssd_funcs_default(*sLibmdnssdFuncs);
    }
#else   // !__linux__
    LOG(INFO) << "Using Bonjour dns-sd";
    adb_dnssd_funcs_default(*sLibmdnssdFuncs);
#endif  // __linux__
    return &*sLibmdnssdFuncs;
}

}  // namespace mdns
