// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_SERVER_PROPERTIES_H_
#define NET_HTTP_HTTP_SERVER_PROPERTIES_H_

#include <stdint.h>

#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "base/containers/mru_cache.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_server_id.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_framer.h"  // TODO(willchan): Reconsider this.
#include "net/spdy/spdy_protocol.h"
#include "url/scheme_host_port.h"

namespace base {
class Value;
}

namespace net {

class IPAddress;
struct SSLConfig;

enum AlternateProtocolUsage {
  // Alternate Protocol was used without racing a normal connection.
  ALTERNATE_PROTOCOL_USAGE_NO_RACE = 0,
  // Alternate Protocol was used by winning a race with a normal connection.
  ALTERNATE_PROTOCOL_USAGE_WON_RACE = 1,
  // Alternate Protocol was not used by losing a race with a normal connection.
  ALTERNATE_PROTOCOL_USAGE_LOST_RACE = 2,
  // Alternate Protocol was not used because no Alternate-Protocol information
  // was available when the request was issued, but an Alternate-Protocol header
  // was present in the response.
  ALTERNATE_PROTOCOL_USAGE_MAPPING_MISSING = 3,
  // Alternate Protocol was not used because it was marked broken.
  ALTERNATE_PROTOCOL_USAGE_BROKEN = 4,
  // Maximum value for the enum.
  ALTERNATE_PROTOCOL_USAGE_MAX,
};

// Log a histogram to reflect |usage|.
NET_EXPORT void HistogramAlternateProtocolUsage(AlternateProtocolUsage usage);

enum BrokenAlternateProtocolLocation {
  BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_STREAM_FACTORY_IMPL_JOB = 0,
  BROKEN_ALTERNATE_PROTOCOL_LOCATION_QUIC_STREAM_FACTORY = 1,
  BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_STREAM_FACTORY_IMPL_JOB_ALT = 2,
  BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_STREAM_FACTORY_IMPL_JOB_MAIN = 3,
  BROKEN_ALTERNATE_PROTOCOL_LOCATION_MAX,
};

// Log a histogram to reflect |location|.
NET_EXPORT void HistogramBrokenAlternateProtocolLocation(
    BrokenAlternateProtocolLocation location);

enum AlternateProtocol {
  NPN_SPDY_3_1,
  ALTERNATE_PROTOCOL_MINIMUM_VALID_VERSION = NPN_SPDY_3_1,
  NPN_SPDY_MINIMUM_VERSION = NPN_SPDY_3_1,
  NPN_HTTP_2,
  NPN_SPDY_MAXIMUM_VERSION = NPN_HTTP_2,
  QUIC,
  ALTERNATE_PROTOCOL_MAXIMUM_VALID_VERSION = QUIC,
  UNINITIALIZED_ALTERNATE_PROTOCOL,
};

// Simply returns whether |protocol| is between
// ALTERNATE_PROTOCOL_MINIMUM_VALID_VERSION and
// ALTERNATE_PROTOCOL_MAXIMUM_VALID_VERSION (inclusive).
NET_EXPORT bool IsAlternateProtocolValid(AlternateProtocol protocol);

enum AlternateProtocolSize {
  NUM_VALID_ALTERNATE_PROTOCOLS =
    ALTERNATE_PROTOCOL_MAXIMUM_VALID_VERSION -
    ALTERNATE_PROTOCOL_MINIMUM_VALID_VERSION + 1,
};

NET_EXPORT const char* AlternateProtocolToString(AlternateProtocol protocol);
NET_EXPORT AlternateProtocol AlternateProtocolFromString(
    const std::string& str);
NET_EXPORT_PRIVATE AlternateProtocol AlternateProtocolFromNextProto(
    NextProto next_proto);

// (protocol, host, port) triple as defined in
// https://tools.ietf.org/id/draft-ietf-httpbis-alt-svc-06.html
struct NET_EXPORT AlternativeService {
  AlternativeService()
      : protocol(UNINITIALIZED_ALTERNATE_PROTOCOL), host(), port(0) {}

  AlternativeService(AlternateProtocol protocol,
                     const std::string& host,
                     uint16_t port)
      : protocol(protocol), host(host), port(port) {}

  AlternativeService(AlternateProtocol protocol,
                     const HostPortPair& host_port_pair)
      : protocol(protocol),
        host(host_port_pair.host()),
        port(host_port_pair.port()) {}

  AlternativeService(const AlternativeService& alternative_service) = default;
  AlternativeService& operator=(const AlternativeService& alternative_service) =
      default;

  HostPortPair host_port_pair() const { return HostPortPair(host, port); }

  bool operator==(const AlternativeService& other) const {
    return protocol == other.protocol && host == other.host &&
           port == other.port;
  }

  bool operator!=(const AlternativeService& other) const {
    return !this->operator==(other);
  }

  bool operator<(const AlternativeService& other) const {
    return std::tie(protocol, host, port) <
           std::tie(other.protocol, other.host, other.port);
  }

  std::string ToString() const;

  AlternateProtocol protocol;
  std::string host;
  uint16_t port;
};

struct NET_EXPORT AlternativeServiceInfo {
  AlternativeServiceInfo() : alternative_service() {}

  AlternativeServiceInfo(const AlternativeService& alternative_service,
                         base::Time expiration)
      : alternative_service(alternative_service),
        expiration(expiration) {}

  AlternativeServiceInfo(AlternateProtocol protocol,
                         const std::string& host,
                         uint16_t port,
                         base::Time expiration)
      : alternative_service(protocol, host, port),
        expiration(expiration) {}

  AlternativeServiceInfo(
      const AlternativeServiceInfo& alternative_service_info) = default;
  AlternativeServiceInfo& operator=(
      const AlternativeServiceInfo& alternative_service_info) = default;

  bool operator==(const AlternativeServiceInfo& other) const {
    return alternative_service == other.alternative_service &&
           expiration == other.expiration;
  }

  bool operator!=(const AlternativeServiceInfo& other) const {
    return !this->operator==(other);
  }

  std::string ToString() const;

  AlternativeService alternative_service;
  base::Time expiration;
};

struct NET_EXPORT SupportsQuic {
  SupportsQuic() : used_quic(false) {}
  SupportsQuic(bool used_quic, const std::string& address)
      : used_quic(used_quic),
        address(address) {}

  bool Equals(const SupportsQuic& other) const {
    return used_quic == other.used_quic && address == other.address;
  }

  bool used_quic;
  std::string address;
};

struct NET_EXPORT ServerNetworkStats {
  ServerNetworkStats() : bandwidth_estimate(QuicBandwidth::Zero()) {}

  bool operator==(const ServerNetworkStats& other) const {
    return srtt == other.srtt && bandwidth_estimate == other.bandwidth_estimate;
  }

  bool operator!=(const ServerNetworkStats& other) const {
    return !this->operator==(other);
  }

  base::TimeDelta srtt;
  QuicBandwidth bandwidth_estimate;
};

typedef std::vector<AlternativeService> AlternativeServiceVector;
typedef std::vector<AlternativeServiceInfo> AlternativeServiceInfoVector;
typedef base::MRUCache<url::SchemeHostPort, AlternativeServiceInfoVector>
    AlternativeServiceMap;
typedef base::MRUCache<url::SchemeHostPort, SettingsMap> SpdySettingsMap;
typedef base::MRUCache<url::SchemeHostPort, ServerNetworkStats>
    ServerNetworkStatsMap;
typedef base::MRUCache<QuicServerId, std::string> QuicServerInfoMap;

// Persist 5 QUIC Servers. This is mainly used by cronet.
const int kMaxQuicServersToPersist = 5;

extern const char kAlternativeServiceHeader[];

// The interface for setting/retrieving the HTTP server properties.
// Currently, this class manages servers':
// * SPDY support (based on NPN results).
// * alternative service support.
// * SPDY Settings (like CWND ID field).
// * QUIC data (like ServerNetworkStats and QuicServerInfo).
//
// Embedders must ensure that HttpServerProperites is completely initialized
// before the first request is issued.
class NET_EXPORT HttpServerProperties {
 public:
  HttpServerProperties() {}
  virtual ~HttpServerProperties() {}

  // Deletes all data.
  virtual void Clear() = 0;

  // Returns true if |server| supports a network protocol which honors
  // request prioritization.
  virtual bool SupportsRequestPriority(const url::SchemeHostPort& server) = 0;

  // Returns the value set by SetSupportsSpdy(). If not set, returns false.
  virtual bool GetSupportsSpdy(const url::SchemeHostPort& server) = 0;

  // Add |server| into the persistent store. Should only be called from IO
  // thread.
  virtual void SetSupportsSpdy(const url::SchemeHostPort& server,
                               bool support_spdy) = 0;

  // Returns true if |server| has required HTTP/1.1 via HTTP/2 error code.
  virtual bool RequiresHTTP11(const HostPortPair& server) = 0;

  // Require HTTP/1.1 on subsequent connections.  Not persisted.
  virtual void SetHTTP11Required(const HostPortPair& server) = 0;

  // Modify SSLConfig to force HTTP/1.1.
  static void ForceHTTP11(SSLConfig* ssl_config);

  // Modify SSLConfig to force HTTP/1.1 if necessary.
  virtual void MaybeForceHTTP11(const HostPortPair& server,
                                SSLConfig* ssl_config) = 0;

  // Return all alternative services for |origin|, including broken ones.
  // Returned alternative services never have empty hostnames.
  virtual AlternativeServiceVector GetAlternativeServices(
      const url::SchemeHostPort& origin) = 0;

  // Set a single alternative service for |origin|.  Previous alternative
  // services for |origin| are discarded.
  // |alternative_service.host| may be empty.
  // Return true if |alternative_service_map_| is changed.
  virtual bool SetAlternativeService(
      const url::SchemeHostPort& origin,
      const AlternativeService& alternative_service,
      base::Time expiration) = 0;

  // Set alternative services for |origin|.  Previous alternative services for
  // |origin| are discarded.
  // Hostnames in |alternative_service_info_vector| may be empty.
  // Return true if |alternative_service_map_| is changed.
  virtual bool SetAlternativeServices(
      const url::SchemeHostPort& origin,
      const AlternativeServiceInfoVector& alternative_service_info_vector) = 0;

  // Marks |alternative_service| as broken.
  // |alternative_service.host| must not be empty.
  virtual void MarkAlternativeServiceBroken(
      const AlternativeService& alternative_service) = 0;

  // Marks |alternative_service| as recently broken.
  // |alternative_service.host| must not be empty.
  virtual void MarkAlternativeServiceRecentlyBroken(
      const AlternativeService& alternative_service) = 0;

  // Returns true iff |alternative_service| is currently broken.
  // |alternative_service.host| must not be empty.
  virtual bool IsAlternativeServiceBroken(
      const AlternativeService& alternative_service) const = 0;

  // Returns true iff |alternative_service| was recently broken.
  // |alternative_service.host| must not be empty.
  virtual bool WasAlternativeServiceRecentlyBroken(
      const AlternativeService& alternative_service) = 0;

  // Confirms that |alternative_service| is working.
  // |alternative_service.host| must not be empty.
  virtual void ConfirmAlternativeService(
      const AlternativeService& alternative_service) = 0;

  // Returns all alternative service mappings.
  // Returned alternative services may have empty hostnames.
  virtual const AlternativeServiceMap& alternative_service_map() const = 0;

  // Returns all alternative service mappings as human readable strings.
  // Empty alternative service hostnames will be printed as such.
  virtual std::unique_ptr<base::Value> GetAlternativeServiceInfoAsValue()
      const = 0;

  // Gets a reference to the SettingsMap stored for a host.
  // If no settings are stored, returns an empty SettingsMap.
  virtual const SettingsMap& GetSpdySettings(
      const url::SchemeHostPort& server) = 0;

  // Saves an individual SPDY setting for a host. Returns true if SPDY setting
  // is to be persisted.
  virtual bool SetSpdySetting(const url::SchemeHostPort& server,
                              SpdySettingsIds id,
                              SpdySettingsFlags flags,
                              uint32_t value) = 0;

  // Clears all SPDY settings for a host.
  virtual void ClearSpdySettings(const url::SchemeHostPort& server) = 0;

  // Clears all SPDY settings for all hosts.
  virtual void ClearAllSpdySettings() = 0;

  // Returns all persistent SPDY settings.
  virtual const SpdySettingsMap& spdy_settings_map() const = 0;

  virtual bool GetSupportsQuic(IPAddress* last_address) const = 0;

  virtual void SetSupportsQuic(bool used_quic,
                               const IPAddress& last_address) = 0;

  // Sets |stats| for |host_port_pair|.
  virtual void SetServerNetworkStats(const url::SchemeHostPort& server,
                                     ServerNetworkStats stats) = 0;

  virtual const ServerNetworkStats* GetServerNetworkStats(
      const url::SchemeHostPort& server) = 0;

  virtual const ServerNetworkStatsMap& server_network_stats_map() const = 0;

  // Save QuicServerInfo (in std::string form) for the given |server_id|.
  // Returns true if the value has changed otherwise it returns false.
  virtual bool SetQuicServerInfo(const QuicServerId& server_id,
                                 const std::string& server_info) = 0;

  // Get QuicServerInfo (in std::string form) for the given |server_id|.
  virtual const std::string* GetQuicServerInfo(
      const QuicServerId& server_id) = 0;

  // Returns all persistent QuicServerInfo objects.
  virtual const QuicServerInfoMap& quic_server_info_map() const = 0;

  // Returns the number of server configs (QuicServerInfo objects) persisted.
  virtual size_t max_server_configs_stored_in_properties() const = 0;

  // Sets the number of server configs (QuicServerInfo objects) to be persisted.
  virtual void SetMaxServerConfigsStoredInProperties(
      size_t max_server_configs_stored_in_properties) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(HttpServerProperties);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_SERVER_PROPERTIES_H_
