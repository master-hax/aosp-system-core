/*
 * Copyright 2011 Daniel Drown
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * checksum.c - ipv4/ipv6 checksum calculation
 */
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "netutils/checksum.h"

/* function: ip_checksum_add - adds data to a checksum.
 * Odd lengths require little-endian host and even then cannot be further extended.
 *   csum - the current checksum (never 0, use 0xFFFF to start a new checksum)
 *   data - pointer to buffer to add to the checksum
 *   len  - length of buffer
 * returns: a positive 32-bit partial checksum
 */
uint32_t ip_checksum_add(uint32_t csum, const void* data, int len) {
    const uint16_t* data_16 = data;
    int left;

    for (left = len; left >= 2; left -= 2) csum += *(data_16++);
    if (left) csum += *(const uint8_t*)data_16;

    return csum;
}

/* function: ip_checksum_fold - folds a 32-bit partial checksum into 16 bits
 *   csum - sum from ip_checksum_add (never 0)
 *   returns: the folded positive 16-bit partial checksum in network byte order
 */
uint16_t ip_checksum_fold(uint32_t csum) {
    csum = (csum >> 16) + (csum & 0xFFFF);
    return (csum >> 16) + (csum & 0xFFFF);
}

/* function: ip_checksum_finish - folds and closes the checksum
 *   csum - sum from ip_checksum_add (never 0)
 *   returns: a header checksum value in network byte order (never 0xFFFF)
 */
uint16_t ip_checksum_finish(uint32_t csum) {
    return ~ip_checksum_fold(csum);
}

/* function: ip_checksum - combined ip_checksum_add and ip_checksum_finish
 *   data - pointer to buffer to checksum
 *   len  - length of buffer
 */
uint16_t ip_checksum(const void* data, int len) {
    return ip_checksum_finish(ip_checksum_add(0xFFFF, data, len));
}

/* function: ipv6_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp/icmp headers
 *   ip6      - the ipv6 header
 *   len      - the transport length (transport header + payload)
 *   protocol - the transport layer protocol, can be different from ip6->ip6_nxt for fragments
 */
uint32_t ipv6_pseudo_header_checksum(const struct ip6_hdr* ip6, uint32_t len, uint8_t protocol) {
    uint32_t csum = 0xFFFF + htons(protocol) + htons(len & 0xFFFF) + htons(len >> 16);
    csum = ip_checksum_add(csum, &(ip6->ip6_src), sizeof(struct in6_addr));
    return ip_checksum_add(csum, &(ip6->ip6_dst), sizeof(struct in6_addr));
}

/* function: ipv4_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp headers
 *   ip      - the ipv4 header
 *   len     - the transport length (transport header + payload)
 */
uint32_t ipv4_pseudo_header_checksum(const struct iphdr* ip, uint16_t len) {
    uint32_t csum = 0xFFFF + htons(ip->protocol) + htons(len);
    csum = ip_checksum_add(csum, &(ip->saddr), sizeof(uint32_t));
    return ip_checksum_add(csum, &(ip->daddr), sizeof(uint32_t));
}

/* function: ip_checksum_adjust
 * calculates a new checksum given a previous checksum and the old and new pseudo-header checksums
 *   checksum    - the header checksum in the original packet in network byte order
 *   old_hdr_sum - the pseudo-header checksum of the original packet
 *   new_hdr_sum - the pseudo-header checksum of the translated packet
 *   returns: the new header checksum in network byte order
 */
uint16_t ip_checksum_adjust(uint16_t checksum, uint32_t old_hdr_sum, uint32_t new_hdr_sum) {
    // Algorithm suggested in RFC 1624.
    // http://tools.ietf.org/html/rfc1624#section-3
    checksum = ~checksum;
    uint16_t folded_sum = ip_checksum_fold(checksum + new_hdr_sum);
    uint16_t folded_old = ip_checksum_fold(old_hdr_sum);
    if (folded_sum > folded_old) {
        return ~(folded_sum - folded_old);
    } else {
        return ~(folded_sum - folded_old - 1);  // end-around borrow
    }
}
