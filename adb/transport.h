/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <sys/types.h>

#include <chrono>
#include <list>
#include <string>
#include <unordered_set>

#include "adb.h"

typedef std::unordered_set<std::string> FeatureSet;

const FeatureSet& supported_features();

// Encodes and decodes FeatureSet objects into human-readable strings.
std::string FeatureSetToString(const FeatureSet& features);
FeatureSet StringToFeatureSet(const std::string& features_string);

// Returns true if both local features and |feature_set| support |feature|.
bool CanUseFeature(const FeatureSet& feature_set, const std::string& feature);

// Do not use any of [:;=,] in feature strings, they have special meaning
// in the connection banner.
extern const char* const kFeatureShell2;
// The 'cmd' command is available
extern const char* const kFeatureCmd;

using steady_clock = std::chrono::steady_clock;
using time_interval = std::chrono::duration<double>;

enum class HeartbeatStatus {
  WAITING,
  FINISHED,
  INVALID,
};

class atransport {
public:
    // TODO(danalbert): We expose waaaaaaay too much stuff because this was
    // historically just a struct, but making the whole thing a more idiomatic
    // class in one go is a very large change. Given how bad our testing is,
    // it's better to do this piece by piece.

    atransport(size_t heartbeat_interval_in_sec, size_t heartbeat_failed_count_before_invalid)
        : created_time_(std::chrono::steady_clock::now()),
          heartbeat_interval_(heartbeat_interval_in_sec),
          heartbeat_failed_count_before_invalid_(heartbeat_failed_count_before_invalid),
          heartbeat_failed_count_(0) {
        transport_fde = {};
        protocol_version = A_VERSION;
        max_payload = MAX_PAYLOAD;
    }

    virtual ~atransport() {}

    int (*read_from_remote)(apacket* p, atransport* t) = nullptr;
    int (*write_to_remote)(apacket* p, atransport* t) = nullptr;
    void (*close)(atransport* t) = nullptr;
    void (*kick)(atransport* t) = nullptr;

    int fd = -1;
    int transport_socket = -1;
    fdevent transport_fde;
    size_t ref_count = 0;
    uint32_t sync_token = 0;
    ConnectionState connection_state = kCsOffline;
    bool online = false;
    TransportType type = kTransportAny;

    // USB handle or socket fd as needed.
    usb_handle* usb = nullptr;
    int sfd = -1;

    // Used to identify transports for clients.
    char* serial = nullptr;
    char* product = nullptr;
    char* model = nullptr;
    char* device = nullptr;
    char* devpath = nullptr;
    int adb_port = -1;  // Use for emulators (local transport)
    bool kicked = false;

    void* key = nullptr;
    unsigned char token[TOKEN_SIZE] = {};
    size_t failed_auth_attempts = 0;

    const std::string connection_state_name() const;

    void update_version(int version, size_t payload);
    int get_protocol_version() const;
    size_t get_max_payload() const;

    const FeatureSet& features() const {
        return features_;
    }

    bool has_feature(const std::string& feature) const;

    // Loads the transport's feature set from the given string.
    void SetFeatures(const std::string& features_string);

    void AddDisconnect(adisconnect* disconnect);
    void RemoveDisconnect(adisconnect* disconnect);
    void RunDisconnects();

    // Returns true if |target| matches this transport. A matching |target| can be any of:
    //   * <serial>
    //   * <devpath>
    //   * product:<product>
    //   * model:<model>
    //   * device:<device>
    //
    // If this is a local transport, serial will also match [tcp:|udp:]<hostname>[:port] targets.
    // For example, serial "100.100.100.100:5555" would match any of:
    //   * 100.100.100.100
    //   * tcp:100.100.100.100
    //   * udp:100.100.100.100:5555
    // This is to make it easier to use the same network target for both fastboot and adb.
    bool MatchesTarget(const std::string& target) const;

    steady_clock::time_point GetCreatedTime() const {
        return created_time_;
    }

    void SetHeartbeatOpenPacketSentTime(steady_clock::time_point tp) {
        heartbeat_open_packet_sent_time_ = tp;
    }

    void SetHeartbeatClosePacketReceivedTime(steady_clock::time_point tp) {
        heartbeat_close_packet_received_time_ = tp;
    }
    HeartbeatStatus CheckHeartbeatStatus(steady_clock::time_point now);

private:
    // A set of features transmitted in the banner with the initial connection.
    // This is stored in the banner as 'features=feature0,feature1,etc'.
    FeatureSet features_;
    int protocol_version;
    size_t max_payload;

    // A list of adisconnect callbacks called when the transport is kicked.
    std::list<adisconnect*> disconnects_;

    const steady_clock::time_point created_time_;
    const time_interval heartbeat_interval_;
    const size_t heartbeat_failed_count_before_invalid_;
    size_t heartbeat_failed_count_;
    steady_clock::time_point heartbeat_open_packet_sent_time_;
    steady_clock::time_point heartbeat_close_packet_received_time_;

    DISALLOW_COPY_AND_ASSIGN(atransport);
};

/*
 * Obtain a transport from the available transports.
 * If serial is non-null then only the device with that serial will be chosen.
 * If multiple devices/emulators would match, *is_ambiguous (if non-null)
 * is set to true and nullptr returned.
 * If no suitable transport is found, error is set and nullptr returned.
 */
atransport* acquire_one_transport(TransportType type, const char* serial,
                                  bool* is_ambiguous, std::string* error_out);
void kick_transport(atransport* t);
void update_transports(void);

void init_transport_registration(void);
std::string list_transports(bool long_listing);
atransport* find_transport(const char* serial);
void kick_all_tcp_devices();

void register_usb_transport(usb_handle* h, const char* serial,
                            const char* devpath, unsigned writeable);

/* cause new transports to be init'd and added to the list */
int register_socket_transport(int s, const char* serial, int port, int local,
                              size_t heartbeat_internal_in_sec,
                              size_t heartbeat_count_before_fail);

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle* usb);

int check_header(apacket* p, atransport* t);
int check_data(apacket* p);

/* for MacOS X cleanup */
void close_usb_devices();

void send_packet(apacket* p, atransport* t);

asocket* create_device_tracker(void);

#endif   /* __TRANSPORT_H */
