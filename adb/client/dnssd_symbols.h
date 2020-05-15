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

#pragma once

#include <dns_sd.h>

namespace mdns {

struct AdbDnssdFuncs {
    int DNSSD_API (*DNSServiceRefSockFD)(DNSServiceRef sdRef);
    DNSServiceErrorType DNSSD_API (*DNSServiceProcessResult)(DNSServiceRef sdRef);
    void DNSSD_API (*DNSServiceRefDeallocate)(DNSServiceRef sdRef);
    DNSServiceErrorType DNSSD_API (*DNSServiceResolve)(DNSServiceRef* sdRef, DNSServiceFlags flags,
                                                       uint32_t interfaceIndex, const char* name,
                                                       const char* regtype, const char* domain,
                                                       DNSServiceResolveReply callBack,
                                                       void* context);
    DNSServiceErrorType DNSSD_API (*DNSServiceBrowse)(DNSServiceRef* sdRef, DNSServiceFlags flags,
                                                      uint32_t interfaceIndex, const char* regtype,
                                                      const char* domain,
                                                      DNSServiceBrowseReply callBack,
                                                      void* context);

    // The below APIs do not exist in avahi's bonjour compatibility library.
    DNSServiceErrorType DNSSD_API (*DNSServiceGetAddrInfo)(
            DNSServiceRef* sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
            DNSServiceProtocol protocol, const char* hostname, DNSServiceGetAddrInfoReply callBack,
            void* context);
    DNSServiceErrorType DNSSD_API (*DNSServiceGetProperty)(const char* property, void* result,
                                                           uint32_t* size);
};

// For linux, it will try to load the avahi-compat library for bonjour, which contains most of the
// symbols in dns_sd.h. If the library isn't found, this will return the APIs from libmdnssd.
const AdbDnssdFuncs* get_adb_dnssd_funcs();

}  // namespace mdns
