/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <linux/bpf.h>

namespace android {

#define DEFAULT_OVERFLOWUID 65534
#define BPF_PATH "/sys/fs/bpf"

static const char* BPF_UID_STATS_MAP = "/traffic_uid_stats_map";
static const char* BPF_TAG_STATS_MAP = "/traffic_tag_stats_map";

struct StatsKey {
    uint32_t uid;
    uint32_t tag;
    uint32_t counterSet;
    uint32_t ifaceIndex;
};

// TODO: verify if framework side still need the detail number about TCP and UDP
// traffic. If not, remove the related tx/rx bytes and packets field to save
// space and simplify the eBPF program.
struct StatsValue {
    uint64_t rxTcpPackets;
    uint64_t rxTcpBytes;
    uint64_t txTcpPackets;
    uint64_t txTcpBytes;
    uint64_t rxUdpPackets;
    uint64_t rxUdpBytes;
    uint64_t txUdpPackets;
    uint64_t txUdpBytes;
    uint64_t rxOtherPackets;
    uint64_t rxOtherBytes;
    uint64_t txOtherPackets;
    uint64_t txOtherBytes;
};

bool hasBpfSupport();
int findMapEntry(int map_fd, void* key, void* value);
int getNextMapKey(int map_fd, void* key, void* next_key);
int mapRetrieve(const char* pathname, int);

}  // namespace android
