// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_NETWORK_SESSION_H_
#define NET_HTTP_HTTP_NETWORK_SESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/non_thread_safe.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_stream_factory.h"
#include "net/quic/quic_stream_factory.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/ssl/ssl_client_auth_cache.h"

namespace base {
class Value;
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
class ProxyDelegate;
class ProxyService;
class QuicClock;
class QuicCryptoClientStreamFactory;
class QuicServerInfoFactory;
class SocketPerformanceWatcherFactory;
class SOCKSClientSocketPool;
class SSLClientSocketPool;
class SSLConfigService;
class TransportClientSocketPool;
class TransportSecurityState;

// This class holds session objects used by HttpNetworkTransaction objects.
class NET_EXPORT HttpNetworkSession
    : NON_EXPORTED_BASE(public base::NonThreadSafe) {
 public:
  struct NET_EXPORT Params {
    Params();
    Params(const Params& other);
    ~Params();

    ClientSocketFactory* client_socket_factory;
    HostResolver* host_resolver;
    CertVerifier* cert_verifier;
    CTPolicyEnforcer* ct_policy_enforcer;
    ChannelIDService* channel_id_service;
    TransportSecurityState* transport_security_state;
    CTVerifier* cert_transparency_verifier;
    ProxyService* proxy_service;
    SSLConfigService* ssl_config_service;
    HttpAuthHandlerFactory* http_auth_handler_factory;
    base::WeakPtr<HttpServerProperties> http_server_properties;
    NetLog* net_log;
    HostMappingRules* host_mapping_rules;
    SocketPerformanceWatcherFactory* socket_performance_watcher_factory;
    bool ignore_certificate_errors;
    uint16_t testing_fixed_http_port;
    uint16_t testing_fixed_https_port;
    bool enable_tcp_fast_open_for_ssl;

    // Use SPDY ping frames to test for connection health after idle.
    bool enable_spdy_ping_based_connection_checking;
    NextProto spdy_default_protocol;
    bool enable_spdy31;
    bool enable_http2;
    size_t spdy_session_max_recv_window_size;
    size_t spdy_stream_max_recv_window_size;
    // Source of time for SPDY connections.
    SpdySessionPool::TimeFunc time_func;
    // Whether to parse Alt-Svc headers.
    bool parse_alternative_services;
    // Whether to enable Alt-Svc entries with hostname different than that of
    // the origin.
    bool enable_alternative_service_with_different_host;

    // Enables NPN support.  Note that ALPN is always enabled.
    bool enable_npn;

    // Enables Brotli Content-Encoding support.
    bool enable_brotli;

    // Enable setting of HTTP/2 dependencies based on priority.
    bool enable_priority_dependencies;

    // Enables QUIC support.
    bool enable_quic;
    // Disable QUIC if a connection times out with open streams.
    bool disable_quic_on_timeout_with_open_streams;
    // Enables QUIC for proxies.
    bool enable_quic_for_proxies;
    // Instruct QUIC to use consistent ephemeral ports when talking to
    // the same server.
    bool enable_quic_port_selection;
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
    // Specifies the maximum number of connections with high packet loss in
    // a row after which QUIC will be disabled.
    int quic_max_number_of_lossy_connections;
    // Specifies packet loss rate in fraction after which a connection is
    // closed and is considered as a lossy connection.
    float quic_packet_loss_threshold;
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
    int quic_max_recent_disabled_reasons;
    int quic_threshold_public_resets_post_handshake;
    int quic_threshold_timeouts_streams_open;
    // Set of QUIC tags to send in the handshake's connection options.
    QuicTagVector quic_connection_options;
    // If true, all QUIC sessions are closed when any local IP address changes.
    bool quic_close_sessions_on_ip_change;
    // Specifes QUIC idle connection state lifetime.
    int quic_idle_connection_timeout_seconds;
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
    // If true, bidirectional streams over QUIC will be disabled.
    bool quic_disable_bidirectional_streams;

    ProxyDelegate* proxy_delegate;
    // Enable support for Token Binding.
    bool enable_token_binding;
  };

  enum SocketPoolType {
    NORMAL_SOCKET_POOL,
    WEBSOCKET_SOCKET_POOL,
    NUM_SOCKET_POOL_TYPES
  };

  explicit HttpNetworkSession(const Params& params);
  ~HttpNetworkSession();

  HttpAuthCache* http_auth_cache() { return &http_auth_cache_; }
  SSLClientAuthCache* ssl_client_auth_cache() {
    return &ssl_client_auth_cache_;
  }

  void AddResponseDrainer(HttpResponseBodyDrainer* drainer);

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
  base::WeakPtr<HttpServerProperties> http_server_properties() {
    return http_server_properties_;
  }
  HttpStreamFactory* http_stream_factory() {
    return http_stream_factory_.get();
  }
  HttpStreamFactory* http_stream_factory_for_websocket() {
    return http_stream_factory_for_websocket_.get();
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

  bool IsProtocolEnabled(AlternateProtocol protocol) const;

  // Populates |*alpn_protos| with protocols to be used with ALPN.
  void GetAlpnProtos(NextProtoVector* alpn_protos) const;

  // Populates |*npn_protos| with protocols to be used with NPN.
  void GetNpnProtos(NextProtoVector* npn_protos) const;

  // Populates |server_config| and |proxy_config| based on this session and
  // |request|.
  void GetSSLConfig(const HttpRequestInfo& request,
                    SSLConfig* server_config,
                    SSLConfig* proxy_config) const;

 private:
  friend class HttpNetworkSessionPeer;

  ClientSocketPoolManager* GetSocketPoolManager(SocketPoolType pool_type);

  NetLog* const net_log_;
  const base::WeakPtr<HttpServerProperties> http_server_properties_;
  CertVerifier* const cert_verifier_;
  HttpAuthHandlerFactory* const http_auth_handler_factory_;

  // Not const since it's modified by HttpNetworkSessionPeer for testing.
  ProxyService* proxy_service_;
  const scoped_refptr<SSLConfigService> ssl_config_service_;

  HttpAuthCache http_auth_cache_;
  SSLClientAuthCache ssl_client_auth_cache_;
  std::unique_ptr<ClientSocketPoolManager> normal_socket_pool_manager_;
  std::unique_ptr<ClientSocketPoolManager> websocket_socket_pool_manager_;
  QuicStreamFactory quic_stream_factory_;
  SpdySessionPool spdy_session_pool_;
  std::unique_ptr<HttpStreamFactory> http_stream_factory_;
  std::unique_ptr<HttpStreamFactory> http_stream_factory_for_websocket_;
  std::set<HttpResponseBodyDrainer*> response_drainers_;

  NextProtoVector next_protos_;
  bool enabled_protocols_[NUM_VALID_ALTERNATE_PROTOCOLS];

  Params params_;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_NETWORK_SESSION_H_
