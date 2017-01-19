// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_network_session.h"

#include <utility>

#include "base/atomic_sequence_num.h"
#include "base/compiler_specific.h"
#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/memory/memory_coordinator_client_registry.h"
#include "base/memory/ptr_util.h"
#include "base/profiler/scoped_tracker.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/values.h"
#include "net/base/network_throttle_manager_impl.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_response_body_drainer.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/http/url_security_manager.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/chromium/quic_crypto_client_stream_factory.h"
#include "net/quic/chromium/quic_stream_factory.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_tag.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_pool_manager_impl.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session_pool.h"

namespace net {

namespace {

base::StaticAtomicSequenceNumber g_next_shard_id;

ClientSocketPoolManager* CreateSocketPoolManager(
    HttpNetworkSession::SocketPoolType pool_type,
    const HttpNetworkSession::Params& params,
    const std::string& ssl_session_cache_shard) {
  // TODO(yutak): Differentiate WebSocket pool manager and allow more
  // simultaneous connections for WebSockets.
  return new ClientSocketPoolManagerImpl(
      params.net_log,
      params.client_socket_factory ? params.client_socket_factory
                                   : ClientSocketFactory::GetDefaultFactory(),
      params.socket_performance_watcher_factory, params.host_resolver,
      params.cert_verifier, params.channel_id_service,
      params.transport_security_state, params.cert_transparency_verifier,
      params.ct_policy_enforcer, ssl_session_cache_shard,
      params.ssl_config_service, pool_type);
}

}  // unnamed namespace

// The maximum receive window sizes for HTTP/2 sessions and streams.
const int32_t kSpdySessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
const int32_t kSpdyStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB
// QUIC's socket receive buffer size.
// We should adaptively set this buffer size, but for now, we'll use a size
// that seems large enough to receive data at line rate for most connections,
// and does not consume "too much" memory.
const int32_t kQuicSocketReceiveBufferSize = 1024 * 1024;  // 1MB

namespace {

// Keep all HTTP2 parameters in |http2_settings|, even the ones that are not
// implemented, to be sent to the server.
// Set default values for settings that |http2_settings| does not specify.
SettingsMap AddDefaultHttp2Settings(SettingsMap http2_settings) {
  // Set default values only if |http2_settings| does not have
  // a value set for given setting.
  SettingsMap::iterator it = http2_settings.find(SETTINGS_HEADER_TABLE_SIZE);
  if (it == http2_settings.end())
    http2_settings[SETTINGS_HEADER_TABLE_SIZE] = kSpdyMaxHeaderTableSize;

  it = http2_settings.find(SETTINGS_MAX_CONCURRENT_STREAMS);
  if (it == http2_settings.end())
    http2_settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
        kSpdyMaxConcurrentPushedStreams;

  it = http2_settings.find(SETTINGS_INITIAL_WINDOW_SIZE);
  if (it == http2_settings.end())
    http2_settings[SETTINGS_INITIAL_WINDOW_SIZE] = kSpdyStreamMaxRecvWindowSize;

  return http2_settings;
}

}  // unnamed namespace

HttpNetworkSession::Params::Params()
    : client_socket_factory(nullptr),
      host_resolver(nullptr),
      cert_verifier(nullptr),
      channel_id_service(nullptr),
      transport_security_state(nullptr),
      cert_transparency_verifier(nullptr),
      ct_policy_enforcer(nullptr),
      proxy_service(nullptr),
      ssl_config_service(nullptr),
      http_auth_handler_factory(nullptr),
      net_log(nullptr),
      host_mapping_rules(nullptr),
      socket_performance_watcher_factory(nullptr),
      ignore_certificate_errors(false),
      testing_fixed_http_port(0),
      testing_fixed_https_port(0),
      enable_tcp_fast_open_for_ssl(false),
      enable_spdy_ping_based_connection_checking(true),
      enable_http2(true),
      spdy_session_max_recv_window_size(kSpdySessionMaxRecvWindowSize),
      time_func(&base::TimeTicks::Now),
      enable_http2_alternative_service_with_different_host(false),
      enable_quic_alternative_service_with_different_host(true),
      enable_quic(false),
      disable_quic_on_timeout_with_open_streams(false),
      quic_always_require_handshake_confirmation(false),
      quic_disable_connection_pooling(false),
      quic_load_server_info_timeout_srtt_multiplier(0.25f),
      quic_enable_connection_racing(false),
      quic_enable_non_blocking_io(false),
      quic_disable_disk_cache(false),
      quic_prefer_aes(false),
      quic_socket_receive_buffer_size(kQuicSocketReceiveBufferSize),
      quic_delay_tcp_race(true),
      quic_max_server_configs_stored_in_properties(0u),
      quic_clock(nullptr),
      quic_random(nullptr),
      quic_max_packet_length(kDefaultMaxPacketSize),
      enable_user_alternate_protocol_ports(false),
      quic_crypto_client_stream_factory(
          QuicCryptoClientStreamFactory::GetDefaultFactory()),
      quic_close_sessions_on_ip_change(false),
      quic_idle_connection_timeout_seconds(kIdleConnectionTimeoutSeconds),
      quic_reduced_ping_timeout_seconds(kPingTimeoutSecs),
      quic_packet_reader_yield_after_duration_milliseconds(
          kQuicYieldAfterDurationMilliseconds),
      quic_disable_preconnect_if_0rtt(false),
      quic_migrate_sessions_on_network_change(false),
      quic_migrate_sessions_early(false),
      quic_allow_server_migration(false),
      quic_disable_bidirectional_streams(false),
      quic_force_hol_blocking(false),
      quic_race_cert_verification(false),
      quic_do_not_fragment(false),
      proxy_delegate(nullptr),
      enable_token_binding(false),
      http_09_on_non_default_ports_enabled(false),
      restrict_to_one_preconnect_for_proxies(false) {
  quic_supported_versions.push_back(QUIC_VERSION_35);
}

HttpNetworkSession::Params::Params(const Params& other) = default;

HttpNetworkSession::Params::~Params() {}

// TODO(mbelshe): Move the socket factories into HttpStreamFactory.
HttpNetworkSession::HttpNetworkSession(const Params& params)
    : net_log_(params.net_log),
      http_server_properties_(params.http_server_properties),
      cert_verifier_(params.cert_verifier),
      http_auth_handler_factory_(params.http_auth_handler_factory),
      proxy_service_(params.proxy_service),
      ssl_config_service_(params.ssl_config_service),
      push_delegate_(nullptr),
      quic_stream_factory_(
          params.net_log,
          params.host_resolver,
          params.ssl_config_service,
          params.client_socket_factory
              ? params.client_socket_factory
              : ClientSocketFactory::GetDefaultFactory(),
          params.http_server_properties,
          params.proxy_delegate,
          params.cert_verifier,
          params.ct_policy_enforcer,
          params.channel_id_service,
          params.transport_security_state,
          params.cert_transparency_verifier,
          params.socket_performance_watcher_factory,
          params.quic_crypto_client_stream_factory,
          params.quic_random ? params.quic_random : QuicRandom::GetInstance(),
          params.quic_clock ? params.quic_clock : new QuicChromiumClock(),
          params.quic_max_packet_length,
          params.quic_user_agent_id,
          params.quic_supported_versions,
          params.quic_always_require_handshake_confirmation,
          params.quic_disable_connection_pooling,
          params.quic_load_server_info_timeout_srtt_multiplier,
          params.quic_enable_connection_racing,
          params.quic_enable_non_blocking_io,
          params.quic_disable_disk_cache,
          params.quic_prefer_aes,
          params.quic_socket_receive_buffer_size,
          params.quic_delay_tcp_race,
          params.quic_max_server_configs_stored_in_properties,
          params.quic_close_sessions_on_ip_change,
          params.disable_quic_on_timeout_with_open_streams,
          params.quic_idle_connection_timeout_seconds,
          params.quic_reduced_ping_timeout_seconds,
          params.quic_packet_reader_yield_after_duration_milliseconds,
          params.quic_migrate_sessions_on_network_change,
          params.quic_migrate_sessions_early,
          params.quic_allow_server_migration,
          params.quic_force_hol_blocking,
          params.quic_race_cert_verification,
          params.quic_do_not_fragment,
          params.quic_connection_options,
          params.enable_token_binding),
      spdy_session_pool_(params.host_resolver,
                         params.ssl_config_service,
                         params.http_server_properties,
                         params.transport_security_state,
                         params.enable_spdy_ping_based_connection_checking,
                         params.spdy_session_max_recv_window_size,
                         AddDefaultHttp2Settings(params.http2_settings),
                         params.time_func,
                         params.proxy_delegate),
      http_stream_factory_(new HttpStreamFactoryImpl(this, false)),
      http_stream_factory_for_websocket_(new HttpStreamFactoryImpl(this, true)),
      network_stream_throttler_(new NetworkThrottleManagerImpl()),
      params_(params) {
  DCHECK(proxy_service_);
  DCHECK(ssl_config_service_.get());
  CHECK(http_server_properties_);

  const std::string ssl_session_cache_shard =
      "http_network_session/" + base::IntToString(g_next_shard_id.GetNext());
  normal_socket_pool_manager_.reset(CreateSocketPoolManager(
      NORMAL_SOCKET_POOL, params, ssl_session_cache_shard));
  websocket_socket_pool_manager_.reset(CreateSocketPoolManager(
      WEBSOCKET_SOCKET_POOL, params, ssl_session_cache_shard));

  if (params_.enable_http2) {
    next_protos_.push_back(kProtoHTTP2);
  }

  next_protos_.push_back(kProtoHTTP11);

  http_server_properties_->SetMaxServerConfigsStoredInProperties(
      params.quic_max_server_configs_stored_in_properties);

  memory_pressure_listener_.reset(new base::MemoryPressureListener(base::Bind(
      &HttpNetworkSession::OnMemoryPressure, base::Unretained(this))));
  base::MemoryCoordinatorClientRegistry::GetInstance()->Register(this);
}

HttpNetworkSession::~HttpNetworkSession() {
  response_drainers_.clear();
  spdy_session_pool_.CloseAllSessions();
  base::MemoryCoordinatorClientRegistry::GetInstance()->Unregister(this);
}

void HttpNetworkSession::AddResponseDrainer(
    std::unique_ptr<HttpResponseBodyDrainer> drainer) {
  DCHECK(!base::ContainsKey(response_drainers_, drainer.get()));
  HttpResponseBodyDrainer* drainer_ptr = drainer.get();
  response_drainers_[drainer_ptr] = std::move(drainer);
}

void HttpNetworkSession::RemoveResponseDrainer(
    HttpResponseBodyDrainer* drainer) {
  DCHECK(base::ContainsKey(response_drainers_, drainer));
  response_drainers_[drainer].release();
  response_drainers_.erase(drainer);
}

TransportClientSocketPool* HttpNetworkSession::GetTransportSocketPool(
    SocketPoolType pool_type) {
  return GetSocketPoolManager(pool_type)->GetTransportSocketPool();
}

SSLClientSocketPool* HttpNetworkSession::GetSSLSocketPool(
    SocketPoolType pool_type) {
  return GetSocketPoolManager(pool_type)->GetSSLSocketPool();
}

SOCKSClientSocketPool* HttpNetworkSession::GetSocketPoolForSOCKSProxy(
    SocketPoolType pool_type,
    const HostPortPair& socks_proxy) {
  return GetSocketPoolManager(pool_type)->GetSocketPoolForSOCKSProxy(
      socks_proxy);
}

HttpProxyClientSocketPool* HttpNetworkSession::GetSocketPoolForHTTPProxy(
    SocketPoolType pool_type,
    const HostPortPair& http_proxy) {
  return GetSocketPoolManager(pool_type)->GetSocketPoolForHTTPProxy(http_proxy);
}

SSLClientSocketPool* HttpNetworkSession::GetSocketPoolForSSLWithProxy(
    SocketPoolType pool_type,
    const HostPortPair& proxy_server) {
  return GetSocketPoolManager(pool_type)->GetSocketPoolForSSLWithProxy(
      proxy_server);
}

std::unique_ptr<base::Value> HttpNetworkSession::SocketPoolInfoToValue() const {
  // TODO(yutak): Should merge values from normal pools and WebSocket pools.
  return normal_socket_pool_manager_->SocketPoolInfoToValue();
}

std::unique_ptr<base::Value> HttpNetworkSession::SpdySessionPoolInfoToValue()
    const {
  return spdy_session_pool_.SpdySessionPoolInfoToValue();
}

std::unique_ptr<base::Value> HttpNetworkSession::QuicInfoToValue() const {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->Set("sessions", quic_stream_factory_.QuicStreamFactoryInfoToValue());
  dict->SetBoolean("quic_enabled", IsQuicEnabled());
  std::unique_ptr<base::ListValue> connection_options(new base::ListValue);
  for (QuicTagVector::const_iterator it =
           params_.quic_connection_options.begin();
       it != params_.quic_connection_options.end(); ++it) {
    connection_options->AppendString("'" + QuicTagToString(*it) + "'");
  }
  dict->Set("connection_options", std::move(connection_options));

  std::unique_ptr<base::ListValue> origins_to_force_quic_on(
      new base::ListValue);
  for (const auto& origin : params_.origins_to_force_quic_on) {
    origins_to_force_quic_on->AppendString("'" + origin.ToString() + "'");
  }
  dict->Set("origins_to_force_quic_on", std::move(origins_to_force_quic_on));

  dict->SetDouble("load_server_info_timeout_srtt_multiplier",
                  params_.quic_load_server_info_timeout_srtt_multiplier);
  dict->SetBoolean("enable_connection_racing",
                   params_.quic_enable_connection_racing);
  dict->SetBoolean("disable_disk_cache", params_.quic_disable_disk_cache);
  dict->SetBoolean("prefer_aes", params_.quic_prefer_aes);
  dict->SetBoolean("delay_tcp_race", params_.quic_delay_tcp_race);
  dict->SetInteger("max_server_configs_stored_in_properties",
                   params_.quic_max_server_configs_stored_in_properties);
  dict->SetInteger("idle_connection_timeout_seconds",
                   params_.quic_idle_connection_timeout_seconds);
  dict->SetInteger("reduced_ping_timeout_seconds",
                   params_.quic_reduced_ping_timeout_seconds);
  dict->SetInteger(
      "packet_reader_yield_after_duration_milliseconds",
      params_.quic_packet_reader_yield_after_duration_milliseconds);
  dict->SetBoolean("disable_preconnect_if_0rtt",
                   params_.quic_disable_preconnect_if_0rtt);
  dict->SetBoolean("disable_quic_on_timeout_with_open_streams",
                   params_.disable_quic_on_timeout_with_open_streams);
  dict->SetBoolean("is_quic_disabled", quic_stream_factory_.IsQuicDisabled());
  dict->SetBoolean("force_hol_blocking", params_.quic_force_hol_blocking);
  dict->SetBoolean("race_cert_verification",
                   params_.quic_race_cert_verification);
  return std::move(dict);
}

void HttpNetworkSession::CloseAllConnections() {
  normal_socket_pool_manager_->FlushSocketPoolsWithError(ERR_ABORTED);
  websocket_socket_pool_manager_->FlushSocketPoolsWithError(ERR_ABORTED);
  spdy_session_pool_.CloseCurrentSessions(ERR_ABORTED);
  quic_stream_factory_.CloseAllSessions(ERR_ABORTED, QUIC_INTERNAL_ERROR);
}

void HttpNetworkSession::CloseIdleConnections() {
  normal_socket_pool_manager_->CloseIdleSockets();
  websocket_socket_pool_manager_->CloseIdleSockets();
  spdy_session_pool_.CloseCurrentIdleSessions();
}

bool HttpNetworkSession::IsProtocolEnabled(NextProto protocol) const {
  switch (protocol) {
    case kProtoUnknown:
      NOTREACHED();
      return false;
    case kProtoHTTP11:
      return true;
    case kProtoHTTP2:
      return params_.enable_http2;
    case kProtoQUIC:
      return IsQuicEnabled();
  }
  NOTREACHED();
  return false;
}

void HttpNetworkSession::SetServerPushDelegate(
    std::unique_ptr<ServerPushDelegate> push_delegate) {
  DCHECK(!push_delegate_ && push_delegate);

  push_delegate_ = std::move(push_delegate);
  spdy_session_pool_.set_server_push_delegate(push_delegate_.get());
  quic_stream_factory_.set_server_push_delegate(push_delegate_.get());
}

void HttpNetworkSession::GetAlpnProtos(NextProtoVector* alpn_protos) const {
  *alpn_protos = next_protos_;
}

void HttpNetworkSession::GetSSLConfig(const HttpRequestInfo& request,
                                      SSLConfig* server_config,
                                      SSLConfig* proxy_config) const {
  ssl_config_service_->GetSSLConfig(server_config);
  GetAlpnProtos(&server_config->alpn_protos);
  *proxy_config = *server_config;
  if (request.privacy_mode == PRIVACY_MODE_ENABLED) {
    server_config->channel_id_enabled = false;
  } else if (params_.enable_token_binding && params_.channel_id_service) {
    server_config->token_binding_params.push_back(TB_PARAM_ECDSAP256);
  }
}

void HttpNetworkSession::DumpMemoryStats(
    base::trace_event::ProcessMemoryDump* pmd,
    const std::string& parent_absolute_name) const {
  std::string name = base::StringPrintf("net/http_network_session_%p", this);
  base::trace_event::MemoryAllocatorDump* http_network_session_dump =
      pmd->GetAllocatorDump(name);
  if (http_network_session_dump == nullptr) {
    http_network_session_dump = pmd->CreateAllocatorDump(name);
    normal_socket_pool_manager_->DumpMemoryStats(
        pmd, http_network_session_dump->absolute_name());
    spdy_session_pool_.DumpMemoryStats(
        pmd, http_network_session_dump->absolute_name());
  }
  // Create an empty row under parent's dump so size can be attributed correctly
  // if |this| is shared between URLRequestContexts.
  base::trace_event::MemoryAllocatorDump* empty_row_dump =
      pmd->CreateAllocatorDump(base::StringPrintf(
          "%s/http_network_session", parent_absolute_name.c_str()));
  pmd->AddOwnershipEdge(empty_row_dump->guid(),
                        http_network_session_dump->guid());
}

bool HttpNetworkSession::IsQuicEnabled() const {
  return params_.enable_quic;
}

void HttpNetworkSession::DisableQuic() {
  params_.enable_quic = false;
}

ClientSocketPoolManager* HttpNetworkSession::GetSocketPoolManager(
    SocketPoolType pool_type) {
  switch (pool_type) {
    case NORMAL_SOCKET_POOL:
      return normal_socket_pool_manager_.get();
    case WEBSOCKET_SOCKET_POOL:
      return websocket_socket_pool_manager_.get();
    default:
      NOTREACHED();
      break;
  }
  return NULL;
}

void HttpNetworkSession::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level) {
  switch (memory_pressure_level) {
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE:
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE:
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL:
      CloseIdleConnections();
      break;
  }
}

void HttpNetworkSession::OnMemoryStateChange(base::MemoryState state) {
  // TODO(hajimehoshi): When the state changes, adjust the sizes of the caches
  // to reduce the limits. HttpNetworkSession doesn't have the ability to limit
  // at present.
  switch (state) {
    case base::MemoryState::NORMAL:
      break;
    case base::MemoryState::THROTTLED:
      CloseIdleConnections();
      break;
    case base::MemoryState::SUSPENDED:
    // Note: Not supported at present. Fall through.
    case base::MemoryState::UNKNOWN:
      NOTREACHED();
      break;
  }
}

}  // namespace net
