// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_network_session.h"

#include <inttypes.h>

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
#include "base/trace_event/memory_dump_request_args.h"
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
#include "net/spdy/chromium/spdy_session_pool.h"

namespace net {

namespace {

base::StaticAtomicSequenceNumber g_next_shard_id;

ClientSocketPoolManager* CreateSocketPoolManager(
    HttpNetworkSession::SocketPoolType pool_type,
    const HttpNetworkSession::Context& context,
    const std::string& ssl_session_cache_shard) {
  // TODO(yutak): Differentiate WebSocket pool manager and allow more
  // simultaneous connections for WebSockets.
  return new ClientSocketPoolManagerImpl(
      context.net_log,
      context.client_socket_factory ? context.client_socket_factory
                                    : ClientSocketFactory::GetDefaultFactory(),
      context.socket_performance_watcher_factory,
      context.network_quality_provider, context.host_resolver,
      context.cert_verifier, context.channel_id_service,
      context.transport_security_state, context.cert_transparency_verifier,
      context.ct_policy_enforcer, ssl_session_cache_shard,
      context.ssl_config_service, pool_type);
}

}  // unnamed namespace

// The maximum receive window sizes for HTTP/2 sessions and streams.
const int32_t kSpdySessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
const int32_t kSpdyStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB

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
    : enable_server_push_cancellation(false),
      ignore_certificate_errors(false),
      testing_fixed_http_port(0),
      testing_fixed_https_port(0),
      enable_tcp_fast_open_for_ssl(false),
      enable_user_alternate_protocol_ports(false),
      enable_spdy_ping_based_connection_checking(true),
      enable_http2(true),
      spdy_session_max_recv_window_size(kSpdySessionMaxRecvWindowSize),
      time_func(&base::TimeTicks::Now),
      enable_http2_alternative_service(false),
      enable_quic(false),
      quic_max_packet_length(kDefaultMaxPacketSize),
      quic_max_server_configs_stored_in_properties(0u),
      mark_quic_broken_when_network_blackholes(false),
      retry_without_alt_svc_on_quic_errors(false),
      quic_close_sessions_on_ip_change(false),
      quic_idle_connection_timeout_seconds(kIdleConnectionTimeoutSeconds),
      quic_reduced_ping_timeout_seconds(kPingTimeoutSecs),
      quic_packet_reader_yield_after_duration_milliseconds(
          kQuicYieldAfterDurationMilliseconds),
      quic_migrate_sessions_on_network_change(false),
      quic_migrate_sessions_early(false),
      quic_allow_server_migration(false),
      quic_disable_bidirectional_streams(false),
      quic_force_hol_blocking(false),
      quic_race_cert_verification(false),
      quic_do_not_fragment(false),
      quic_estimate_initial_rtt(false),
      enable_token_binding(false),
      http_09_on_non_default_ports_enabled(false) {
  quic_supported_versions.push_back(QUIC_VERSION_37);
}

HttpNetworkSession::Params::Params(const Params& other) = default;

HttpNetworkSession::Params::~Params() {}

HttpNetworkSession::Context::Context()
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
      socket_performance_watcher_factory(nullptr),
      network_quality_provider(nullptr),
      quic_clock(nullptr),
      quic_random(nullptr),
      quic_crypto_client_stream_factory(
          QuicCryptoClientStreamFactory::GetDefaultFactory()),
      proxy_delegate(nullptr) {}

HttpNetworkSession::Context::Context(const Context& other) = default;

HttpNetworkSession::Context::~Context() {}

// TODO(mbelshe): Move the socket factories into HttpStreamFactory.
HttpNetworkSession::HttpNetworkSession(const Params& params,
                                       const Context& context)
    : net_log_(context.net_log),
      http_server_properties_(context.http_server_properties),
      cert_verifier_(context.cert_verifier),
      http_auth_handler_factory_(context.http_auth_handler_factory),
      proxy_service_(context.proxy_service),
      ssl_config_service_(context.ssl_config_service),
      push_delegate_(nullptr),
      quic_stream_factory_(
          context.net_log,
          context.host_resolver,
          context.ssl_config_service,
          context.client_socket_factory
              ? context.client_socket_factory
              : ClientSocketFactory::GetDefaultFactory(),
          context.http_server_properties,
          context.cert_verifier,
          context.ct_policy_enforcer,
          context.channel_id_service,
          context.transport_security_state,
          context.cert_transparency_verifier,
          context.socket_performance_watcher_factory,
          context.quic_crypto_client_stream_factory,
          context.quic_random ? context.quic_random : QuicRandom::GetInstance(),
          context.quic_clock ? context.quic_clock
                             : QuicChromiumClock::GetInstance(),
          params.quic_max_packet_length,
          params.quic_user_agent_id,
          params.quic_supported_versions,
          params.quic_max_server_configs_stored_in_properties > 0,
          params.quic_close_sessions_on_ip_change,
          params.mark_quic_broken_when_network_blackholes,
          params.quic_idle_connection_timeout_seconds,
          params.quic_reduced_ping_timeout_seconds,
          params.quic_packet_reader_yield_after_duration_milliseconds,
          params.quic_migrate_sessions_on_network_change,
          params.quic_migrate_sessions_early,
          params.quic_allow_server_migration,
          params.quic_force_hol_blocking,
          params.quic_race_cert_verification,
          params.quic_do_not_fragment,
          params.quic_estimate_initial_rtt,
          params.quic_connection_options,
          params.enable_token_binding),
      spdy_session_pool_(context.host_resolver,
                         context.ssl_config_service,
                         context.http_server_properties,
                         context.transport_security_state,
                         params.enable_spdy_ping_based_connection_checking,
                         params.spdy_session_max_recv_window_size,
                         AddDefaultHttp2Settings(params.http2_settings),
                         params.time_func,
                         context.proxy_delegate),
      http_stream_factory_(new HttpStreamFactoryImpl(this, false)),
      http_stream_factory_for_websocket_(new HttpStreamFactoryImpl(this, true)),
      network_stream_throttler_(new NetworkThrottleManagerImpl()),
      params_(params),
      context_(context) {
  DCHECK(proxy_service_);
  DCHECK(ssl_config_service_.get());
  CHECK(http_server_properties_);

  const std::string ssl_session_cache_shard =
      "http_network_session/" + base::IntToString(g_next_shard_id.GetNext());
  normal_socket_pool_manager_.reset(CreateSocketPoolManager(
      NORMAL_SOCKET_POOL, context, ssl_session_cache_shard));
  websocket_socket_pool_manager_.reset(CreateSocketPoolManager(
      WEBSOCKET_SOCKET_POOL, context, ssl_session_cache_shard));

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
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
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

  auto connection_options(base::MakeUnique<base::ListValue>());
  for (const auto& option : params_.quic_connection_options)
    connection_options->AppendString(QuicTagToString(option));
  dict->Set("connection_options", std::move(connection_options));

  auto supported_versions(base::MakeUnique<base::ListValue>());
  for (const auto& version : params_.quic_supported_versions)
    supported_versions->AppendString(QuicVersionToString(version));
  dict->Set("supported_versions", std::move(supported_versions));

  auto origins_to_force_quic_on(base::MakeUnique<base::ListValue>());
  for (const auto& origin : params_.origins_to_force_quic_on)
    origins_to_force_quic_on->AppendString(origin.ToString());
  dict->Set("origins_to_force_quic_on", std::move(origins_to_force_quic_on));

  dict->SetInteger("max_packet_length", params_.quic_max_packet_length);
  dict->SetInteger("max_server_configs_stored_in_properties",
                   params_.quic_max_server_configs_stored_in_properties);
  dict->SetInteger("idle_connection_timeout_seconds",
                   params_.quic_idle_connection_timeout_seconds);
  dict->SetInteger("reduced_ping_timeout_seconds",
                   params_.quic_reduced_ping_timeout_seconds);
  dict->SetInteger(
      "packet_reader_yield_after_duration_milliseconds",
      params_.quic_packet_reader_yield_after_duration_milliseconds);

  dict->SetBoolean("mark_quic_broken_when_network_blackholes",
                   params_.mark_quic_broken_when_network_blackholes);
  dict->SetBoolean("retry_without_alt_svc_on_quic_errors",
                   params_.retry_without_alt_svc_on_quic_errors);
  dict->SetBoolean("race_cert_verification",
                   params_.quic_race_cert_verification);
  dict->SetBoolean("disable_bidirectional_streams",
                   params_.quic_disable_bidirectional_streams);
  dict->SetBoolean("close_sessions_on_ip_change",
                   params_.quic_close_sessions_on_ip_change);
  dict->SetBoolean("migrate_sessions_on_network_change",
                   params_.quic_migrate_sessions_on_network_change);
  dict->SetBoolean("migrate_sessions_early",
                   params_.quic_migrate_sessions_early);
  dict->SetBoolean("allow_server_migration",
                   params_.quic_allow_server_migration);
  dict->SetBoolean("do_not_fragment", params_.quic_do_not_fragment);
  dict->SetBoolean("estimate_initial_rtt", params_.quic_estimate_initial_rtt);
  dict->SetBoolean("force_hol_blocking", params_.quic_force_hol_blocking);
  dict->SetBoolean("server_push_cancellation",
                   params_.enable_server_push_cancellation);

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
  DCHECK(push_delegate);
  if (!params_.enable_server_push_cancellation || push_delegate_)
    return;

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
  } else if (params_.enable_token_binding && context_.channel_id_service) {
    server_config->token_binding_params.push_back(TB_PARAM_ECDSAP256);
  }
}

void HttpNetworkSession::DumpMemoryStats(
    base::trace_event::ProcessMemoryDump* pmd,
    const std::string& parent_absolute_name) const {
  std::string name = base::StringPrintf("net/http_network_session_0x%" PRIxPTR,
                                        reinterpret_cast<uintptr_t>(this));
  base::trace_event::MemoryAllocatorDump* http_network_session_dump =
      pmd->GetAllocatorDump(name);
  if (http_network_session_dump == nullptr) {
    http_network_session_dump = pmd->CreateAllocatorDump(name);
    normal_socket_pool_manager_->DumpMemoryStats(
        pmd, http_network_session_dump->absolute_name());
    spdy_session_pool_.DumpMemoryStats(
        pmd, http_network_session_dump->absolute_name());
    if (http_stream_factory_) {
      http_stream_factory_->DumpMemoryStats(
          pmd, http_network_session_dump->absolute_name());
    }
    quic_stream_factory_.DumpMemoryStats(
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

void HttpNetworkSession::OnPurgeMemory() {
  CloseIdleConnections();
}

}  // namespace net
