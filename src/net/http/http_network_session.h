// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_NETWORK_SESSION_H_
#define NET_HTTP_HTTP_NETWORK_SESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#include "base/bind.h"
#include "base/memory/memory_coordinator_client.h"
#include "base/memory/memory_pressure_monitor.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/non_thread_safe.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_stream_factory.h"
#include "net/quic/chromium/quic_stream_factory.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/ssl/ssl_client_auth_cache.h"

namespace base {
class Value;
namespace trace_event {
class ProcessMemoryDump;
}
}

namespace net {

class CTPolicyEnforcer;
class CertVerifier;
class ChannelIDService;
class ClientSocketFactory;
class ClientSocketPoolManager;
class CTVerifier;
class HostResolver;
class HttpAuthHandlerFactory;
class HttpNetworkSessionPeer;
class HttpProxyClientSocketPool;
class HttpResponseBodyDrainer;
class HttpServerProperties;
class NetLog;
class NetworkThrottleManager;
class ProxyDelegate;
class ProxyService;
class QuicClock;
class QuicCryptoClientStreamFactory;
class SocketPerformanceWatcherFactory;
class SOCKSClientSocketPool;
class SSLClientSocketPool;
class SSLConfigService;
class TransportClientSocketPool;
class TransportSecurityState;

// Specifies the maximum HPACK dynamic table size the server is allowed to set.
const uint32_t kSpdyMaxHeaderTableSize = 64 * 1024;

// Specifies the maximum concurrent streams server could send (via push).
const uint32_t kSpdyMaxConcurrentPushedStreams = 1000;

// This class holds session objects used by HttpNetworkTransaction objects.
class NET_EXPORT HttpNetworkSession
    : NON_EXPORTED_BASE(public base::NonThreadSafe),
      public base::MemoryCoordinatorClient {
 public:
  struct NET_EXPORT Params {
    Params();
    Params(const Params& other);
    ~Params();

    ClientSocketFactory* client_socket_factory;
    HostResolver* host_resolver;
    CertVerifier* cert_verifier;
    ChannelIDService* channel_id_service;
    TransportSecurityState* transport_security_state;
    CTVerifier* cert_transparency_verifier;
    CTPolicyEnforcer* ct_policy_enforcer;
    ProxyService* proxy_service;
    SSLConfigService* ssl_config_service;
    HttpAuthHandlerFactory* http_auth_handler_factory;
    HttpServerProperties* http_server_properties;
    NetLog* net_log;
    HostMappingRules* host_mapping_rules;
    SocketPerformanceWatcherFactory* socket_performance_watcher_factory;
    bool ignore_certificate_errors;
    uint16_t testing_fixed_http_port;
    uint16_t testing_fixed_https_port;
    bool enable_tcp_fast_open_for_ssl;

    // Use SPDY ping frames to test for connection health after idle.
    bool enable_spdy_ping_based_connection_checking;
    bool enable_http2;
    size_t spdy_session_max_recv_window_size;
    // HTTP/2 connection settings.
    // Unknown settings will still be sent to the server.
    SettingsMap http2_settings;
    // Source of time for SPDY connections.
    SpdySessionPool::TimeFunc time_func;
    // Whether to enable HTTP/2 Alt-Svc entries with hostname different than
    // that of the origin.
    bool enable_http2_alternative_service_with_different_host;
    // Whether to enable QUIC Alt-Svc entries with hostname different than that
    // of the origin.
    bool enable_quic_alternative_service_with_different_host;

    // Enables QUIC support.
    bool enable_quic;
    // Disable QUIC if a connection times out with open streams.
    bool disable_quic_on_timeout_with_open_streams;
    // Disables QUIC's 0-RTT behavior.
    bool quic_always_require_handshake_confirmation;
    // Disables QUIC connection pooling.
    bool quic_disable_connection_pooling;
    // If not zero, the task to load QUIC server configs from the disk cache
    // will timeout after this value multiplied by the smoothed RTT for the
    // server.
    float quic_load_server_info_timeout_srtt_multiplier;
    // Causes QUIC to race reading the server config from disk with
    // sending an inchoate CHLO.
    bool quic_enable_connection_racing;
    // Use non-blocking IO for UDP sockets.
    bool quic_enable_non_blocking_io;
    // Disables using the disk cache to store QUIC server configs.
    bool quic_disable_disk_cache;
    // Prefer AES-GCM to ChaCha20 even if no hardware support is present.
    bool quic_prefer_aes;
    // Size in bytes of the QUIC DUP socket receive buffer.
    int quic_socket_receive_buffer_size;
    // Delay starting a TCP connection when QUIC believes it can speak
    // 0-RTT to a server.
    bool quic_delay_tcp_race;
    // Maximum number of server configs that are to be stored in
    // HttpServerProperties, instead of the disk cache.
    size_t quic_max_server_configs_stored_in_properties;
    // If not empty, QUIC will be used for all connections to the set of
    // origins in |origins_to_force_quic_on|.
    std::set<HostPortPair> origins_to_force_quic_on;
    // Source of time for QUIC connections. Will be owned by QuicStreamFactory.
    QuicClock* quic_clock;
    // Source of entropy for QUIC connections.
    QuicRandom* quic_random;
    // Limit on the size of QUIC packets.
    size_t quic_max_packet_length;
    // User agent description to send in the QUIC handshake.
    std::string quic_user_agent_id;
    bool enable_user_alternate_protocol_ports;
    // Optional factory to use for creating QuicCryptoClientStreams.
    QuicCryptoClientStreamFactory* quic_crypto_client_stream_factory;
    // Versions of QUIC which may be used.
    QuicVersionVector quic_supported_versions;
    // Set of QUIC tags to send in the handshake's connection options.
    QuicTagVector quic_connection_options;
    // If true, all QUIC sessions are closed when any local IP address changes.
    bool quic_close_sessions_on_ip_change;
    // Specifies QUIC idle connection state lifetime.
    int quic_idle_connection_timeout_seconds;
    // Specifies the reduced ping timeout subsequent connections should use when
    // a connection was timed out with open streams.
    int quic_reduced_ping_timeout_seconds;
    // Specifies the maximum time duration that QUIC packet reader can perform
    // consecutive packets reading.
    int quic_packet_reader_yield_after_duration_milliseconds;
    // If true, disable preconnections if QUIC can do 0RTT.
    bool quic_disable_preconnect_if_0rtt;
    // List of hosts for which QUIC is explicitly whitelisted.
    std::unordered_set<std::string> quic_host_whitelist;
    // If true, active QUIC sessions may be migrated onto a new network when
    // the platform indicates that the default network is changing.
    bool quic_migrate_sessions_on_network_change;
    // If true, active QUIC sessions experiencing poor connectivity may be
    // migrated onto a new network.
    bool quic_migrate_sessions_early;
    // If true, allows migration of QUIC connections to a server-specified
    // alternate server address.
    bool quic_allow_server_migration;
    // If true, bidirectional streams over QUIC will be disabled.
    bool quic_disable_bidirectional_streams;
    // If true, enable force HOL blocking.  For measurement purposes.
    bool quic_force_hol_blocking;
    // If true, race cert verification with host resolution.
    bool quic_race_cert_verification;
    // If true, configure QUIC sockets to not fragment packets.
    bool quic_do_not_fragment;
    // If true, alternative service is not marked as broken if the alternative
    // job fails due to a network change event.
    bool quic_do_not_mark_as_broken_on_network_change;
    // If true, estimate the initial RTT for QUIC connections based on network.
    bool quic_estimate_initial_rtt;

    ProxyDelegate* proxy_delegate;
    // Enable support for Token Binding.
    bool enable_token_binding;

    // Enable HTTP/0.9 for HTTP/HTTPS on ports other than the default one for
    // each protocol.
    bool http_09_on_non_default_ports_enabled;

    // If true, only one pending preconnect is allowed to proxies that support
    // request priorities.
    bool restrict_to_one_preconnect_for_proxies;
  };

  enum SocketPoolType {
    NORMAL_SOCKET_POOL,
    WEBSOCKET_SOCKET_POOL,
    NUM_SOCKET_POOL_TYPES
  };

  explicit HttpNetworkSession(const Params& params);
  ~HttpNetworkSession() override;

  HttpAuthCache* http_auth_cache() { return &http_auth_cache_; }
  SSLClientAuthCache* ssl_client_auth_cache() {
    return &ssl_client_auth_cache_;
  }

  void AddResponseDrainer(std::unique_ptr<HttpResponseBodyDrainer> drainer);

  // Removes the drainer from the session. Does not dispose of it.
  void RemoveResponseDrainer(HttpResponseBodyDrainer* drainer);

  TransportClientSocketPool* GetTransportSocketPool(SocketPoolType pool_type);
  SSLClientSocketPool* GetSSLSocketPool(SocketPoolType pool_type);
  SOCKSClientSocketPool* GetSocketPoolForSOCKSProxy(
      SocketPoolType pool_type,
      const HostPortPair& socks_proxy);
  HttpProxyClientSocketPool* GetSocketPoolForHTTPProxy(
      SocketPoolType pool_type,
      const HostPortPair& http_proxy);
  SSLClientSocketPool* GetSocketPoolForSSLWithProxy(
      SocketPoolType pool_type,
      const HostPortPair& proxy_server);

  CertVerifier* cert_verifier() { return cert_verifier_; }
  ProxyService* proxy_service() { return proxy_service_; }
  SSLConfigService* ssl_config_service() { return ssl_config_service_.get(); }
  SpdySessionPool* spdy_session_pool() { return &spdy_session_pool_; }
  QuicStreamFactory* quic_stream_factory() { return &quic_stream_factory_; }
  HttpAuthHandlerFactory* http_auth_handler_factory() {
    return http_auth_handler_factory_;
  }
  HttpServerProperties* http_server_properties() {
    return http_server_properties_;
  }
  HttpStreamFactory* http_stream_factory() {
    return http_stream_factory_.get();
  }
  HttpStreamFactory* http_stream_factory_for_websocket() {
    return http_stream_factory_for_websocket_.get();
  }
  NetworkThrottleManager* throttler() {
    return network_stream_throttler_.get();
  }
  NetLog* net_log() {
    return net_log_;
  }

  // Creates a Value summary of the state of the socket pools.
  std::unique_ptr<base::Value> SocketPoolInfoToValue() const;

  // Creates a Value summary of the state of the SPDY sessions.
  std::unique_ptr<base::Value> SpdySessionPoolInfoToValue() const;

  // Creates a Value summary of the state of the QUIC sessions and
  // configuration.
  std::unique_ptr<base::Value> QuicInfoToValue() const;

  void CloseAllConnections();
  void CloseIdleConnections();

  // Returns the original Params used to construct this session.
  const Params& params() const { return params_; }

  bool IsProtocolEnabled(NextProto protocol) const;

  void SetServerPushDelegate(std::unique_ptr<ServerPushDelegate> push_delegate);

  // Populates |*alpn_protos| with protocols to be used with ALPN.
  void GetAlpnProtos(NextProtoVector* alpn_protos) const;

  // Populates |server_config| and |proxy_config| based on this session and
  // |request|.
  void GetSSLConfig(const HttpRequestInfo& request,
                    SSLConfig* server_config,
                    SSLConfig* proxy_config) const;

  // Dumps memory allocation stats. |parent_dump_absolute_name| is the name
  // used by the parent MemoryAllocatorDump in the memory dump hierarchy.
  void DumpMemoryStats(base::trace_event::ProcessMemoryDump* pmd,
                       const std::string& parent_absolute_name) const;

  // Evaluates if QUIC is enabled for new streams.
  bool IsQuicEnabled() const;

  // Disable QUIC for new streams.
  void DisableQuic();

 private:
  friend class HttpNetworkSessionPeer;

  ClientSocketPoolManager* GetSocketPoolManager(SocketPoolType pool_type);

  // Flush sockets on low memory notifications callback.
  void OnMemoryPressure(
      base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level);

  // base::MemoryCoordinatorClient implementation:
  void OnPurgeMemory() override;

  NetLog* const net_log_;
  HttpServerProperties* const http_server_properties_;
  CertVerifier* const cert_verifier_;
  HttpAuthHandlerFactory* const http_auth_handler_factory_;

  // Not const since it's modified by HttpNetworkSessionPeer for testing.
  ProxyService* proxy_service_;
  const scoped_refptr<SSLConfigService> ssl_config_service_;

  HttpAuthCache http_auth_cache_;
  SSLClientAuthCache ssl_client_auth_cache_;
  std::unique_ptr<ClientSocketPoolManager> normal_socket_pool_manager_;
  std::unique_ptr<ClientSocketPoolManager> websocket_socket_pool_manager_;
  std::unique_ptr<ServerPushDelegate> push_delegate_;
  QuicStreamFactory quic_stream_factory_;
  SpdySessionPool spdy_session_pool_;
  std::unique_ptr<HttpStreamFactory> http_stream_factory_;
  std::unique_ptr<HttpStreamFactory> http_stream_factory_for_websocket_;
  std::map<HttpResponseBodyDrainer*, std::unique_ptr<HttpResponseBodyDrainer>>
      response_drainers_;
  std::unique_ptr<NetworkThrottleManager> network_stream_throttler_;

  NextProtoVector next_protos_;

  Params params_;

  std::unique_ptr<base::MemoryPressureListener> memory_pressure_listener_;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_NETWORK_SESSION_H_
