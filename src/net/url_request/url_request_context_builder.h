// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class is useful for building a simple URLRequestContext. Most creators
// of new URLRequestContexts should use this helper class to construct it. Call
// any configuration params, and when done, invoke Build() to construct the
// URLRequestContext. This URLRequestContext will own all its own storage.
//
// URLRequestContextBuilder and its associated params classes are initially
// populated with "sane" default values. Read through the comments to figure out
// what these are.

#ifndef NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_H_
#define NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "build/build_config.h"
#include "net/base/net_export.h"
#include "net/base/network_delegate.h"
#include "net/base/proxy_delegate.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_network_session.h"
#include "net/net_features.h"
#include "net/proxy/proxy_config_service.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/core/quic_packets.h"
#include "net/socket/next_proto.h"
#include "net/url_request/url_request_job_factory.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace net {

class CertVerifier;
class ChannelIDService;
class CookieStore;
class CTVerifier;
class HostMappingRules;
class HttpAuthHandlerFactory;
class HttpServerProperties;
class ProxyConfigService;
class SocketPerformanceWatcherFactory;
class URLRequestContext;
class URLRequestInterceptor;

class NET_EXPORT URLRequestContextBuilder {
 public:
  struct NET_EXPORT HttpCacheParams {
    enum Type {
      // In-memory cache.
      IN_MEMORY,
      // Disk cache using "default" backend.
      DISK,
      // Disk cache using "simple" backend (SimpleBackendImpl).
      DISK_SIMPLE,
    };

    HttpCacheParams();
    ~HttpCacheParams();

    // The type of HTTP cache. Default is IN_MEMORY.
    Type type;

    // The max size of the cache in bytes. Default is algorithmically determined
    // based off available disk space.
    int max_size;

    // The cache path (when type is DISK).
    base::FilePath path;
  };

  struct NET_EXPORT HttpNetworkSessionParams {
    HttpNetworkSessionParams();
    ~HttpNetworkSessionParams();

    // These fields mirror those in HttpNetworkSession::Params;
    bool ignore_certificate_errors;
    HostMappingRules* host_mapping_rules;
    uint16_t testing_fixed_http_port;
    uint16_t testing_fixed_https_port;
    bool enable_http2;
    bool enable_quic;
    std::string quic_user_agent_id;
    int quic_max_server_configs_stored_in_properties;
    bool quic_delay_tcp_race;
    std::unordered_set<std::string> quic_host_whitelist;
    bool quic_prefer_aes;
    int quic_idle_connection_timeout_seconds;
    QuicTagVector quic_connection_options;
    bool quic_close_sessions_on_ip_change;
    bool quic_migrate_sessions_on_network_change;
    bool quic_migrate_sessions_early;
    bool quic_disable_bidirectional_streams;
    bool quic_race_cert_verification;
  };

  URLRequestContextBuilder();
  ~URLRequestContextBuilder();

  // Extracts the component pointers required to construct an HttpNetworkSession
  // and copies them into the Params used to create the session. This function
  // should be used to ensure that a context and its associated
  // HttpNetworkSession are consistent.
  static void SetHttpNetworkSessionComponents(
      const URLRequestContext* context,
      HttpNetworkSession::Params* params);

  // These functions are mutually exclusive.  The ProxyConfigService, if
  // set, will be used to construct a ProxyService.
  void set_proxy_config_service(
      std::unique_ptr<ProxyConfigService> proxy_config_service) {
    proxy_config_service_ = std::move(proxy_config_service);
  }
  void set_proxy_service(std::unique_ptr<ProxyService> proxy_service) {
    proxy_service_ = std::move(proxy_service);
  }

  // Call these functions to specify hard-coded Accept-Language
  // or User-Agent header values for all requests that don't
  // have the headers already set.
  void set_accept_language(const std::string& accept_language) {
    accept_language_ = accept_language;
  }
  void set_user_agent(const std::string& user_agent) {
    user_agent_ = user_agent;
  }

  // Control support for data:// requests. By default it's disabled.
  void set_data_enabled(bool enable) {
    data_enabled_ = enable;
  }

#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
  // Control support for file:// requests. By default it's disabled.
  void set_file_enabled(bool enable) {
    file_enabled_ = enable;
  }
#endif

#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
  // Control support for ftp:// requests. By default it's disabled.
  void set_ftp_enabled(bool enable) {
    ftp_enabled_ = enable;
  }
#endif

  // Sets a valid ProtocolHandler for a scheme.
  // A ProtocolHandler already exists for |scheme| will be overwritten.
  void SetProtocolHandler(
      const std::string& scheme,
      std::unique_ptr<URLRequestJobFactory::ProtocolHandler> protocol_handler);

  // Unlike the other setters, the builder does not take ownership of the
  // NetLog.
  // TODO(mmenke):  Probably makes sense to get rid of this, and have consumers
  // set their own NetLog::Observers instead.
  void set_net_log(NetLog* net_log) { net_log_ = net_log; }

  // By default host_resolver is constructed with CreateDefaultResolver.
  void set_host_resolver(std::unique_ptr<HostResolver> host_resolver) {
    host_resolver_ = std::move(host_resolver);
  }

  // Uses BasicNetworkDelegate by default. Note that calling Build will unset
  // any custom delegate in builder, so this must be called each time before
  // Build is called.
  void set_network_delegate(std::unique_ptr<NetworkDelegate> delegate) {
    network_delegate_ = std::move(delegate);
  }

  // Temporarily stores a ProxyDelegate. Ownership is transferred to
  // UrlRequestContextStorage during Build.
  void set_proxy_delegate(std::unique_ptr<ProxyDelegate> delegate) {
    proxy_delegate_ = std::move(delegate);
  }

  // Sets a specific HttpAuthHandlerFactory to be used by the URLRequestContext
  // rather than the default |HttpAuthHandlerRegistryFactory|. The builder
  // takes ownership of the factory and will eventually transfer it to the new
  // URLRequestContext. Note that since Build will transfer ownership, the
  // custom factory will be unset and this must be called before the next Build
  // to set another custom one.
  void SetHttpAuthHandlerFactory(
      std::unique_ptr<HttpAuthHandlerFactory> factory);

  // By default HttpCache is enabled with a default constructed HttpCacheParams.
  void EnableHttpCache(const HttpCacheParams& params);
  void DisableHttpCache();

  // Override default HttpNetworkSession::Params settings.
  void set_http_network_session_params(
      const HttpNetworkSessionParams& http_network_session_params) {
    http_network_session_params_ = http_network_session_params;
  }

  void set_transport_security_persister_path(
      const base::FilePath& transport_security_persister_path) {
    transport_security_persister_path_ = transport_security_persister_path;
  }

  void SetSpdyAndQuicEnabled(bool spdy_enabled,
                             bool quic_enabled);

  void set_quic_connection_options(
      const QuicTagVector& quic_connection_options) {
    http_network_session_params_.quic_connection_options =
        quic_connection_options;
  }

  void set_quic_user_agent_id(const std::string& quic_user_agent_id) {
    http_network_session_params_.quic_user_agent_id = quic_user_agent_id;
  }

  void set_quic_max_server_configs_stored_in_properties(
      int quic_max_server_configs_stored_in_properties) {
    http_network_session_params_.quic_max_server_configs_stored_in_properties =
        quic_max_server_configs_stored_in_properties;
  }

  void set_quic_delay_tcp_race(bool quic_delay_tcp_race) {
    http_network_session_params_.quic_delay_tcp_race = quic_delay_tcp_race;
  }

  void set_quic_idle_connection_timeout_seconds(
      int quic_idle_connection_timeout_seconds) {
    http_network_session_params_.quic_idle_connection_timeout_seconds =
        quic_idle_connection_timeout_seconds;
  }

  void set_quic_host_whitelist(
      const std::unordered_set<std::string>& quic_host_whitelist) {
    http_network_session_params_.quic_host_whitelist = quic_host_whitelist;
  }

  void set_quic_close_sessions_on_ip_change(
      bool quic_close_sessions_on_ip_change) {
    http_network_session_params_.quic_close_sessions_on_ip_change =
        quic_close_sessions_on_ip_change;
  }

  void set_quic_migrate_sessions_on_network_change(
      bool quic_migrate_sessions_on_network_change) {
    http_network_session_params_.quic_migrate_sessions_on_network_change =
        quic_migrate_sessions_on_network_change;
  }

  void set_quic_prefer_aes(bool quic_prefer_aes) {
    http_network_session_params_.quic_prefer_aes = quic_prefer_aes;
  }

  void set_quic_migrate_sessions_early(bool quic_migrate_sessions_early) {
    http_network_session_params_.quic_migrate_sessions_early =
        quic_migrate_sessions_early;
  }

  void set_quic_disable_bidirectional_streams(
      bool quic_disable_bidirectional_streams) {
    http_network_session_params_.quic_disable_bidirectional_streams =
        quic_disable_bidirectional_streams;
  }

  void set_quic_race_cert_verification(bool quic_race_cert_verification) {
    http_network_session_params_.quic_race_cert_verification =
        quic_race_cert_verification;
  }

  void set_throttling_enabled(bool throttling_enabled) {
    throttling_enabled_ = throttling_enabled;
  }

  void set_socket_performance_watcher_factory(
      SocketPerformanceWatcherFactory* socket_performance_watcher_factory) {
    socket_performance_watcher_factory_ = socket_performance_watcher_factory;
  }

  void set_ct_verifier(std::unique_ptr<CTVerifier> ct_verifier);

  void SetCertVerifier(std::unique_ptr<CertVerifier> cert_verifier);

  void SetInterceptors(std::vector<std::unique_ptr<URLRequestInterceptor>>
                           url_request_interceptors);

  // Override the default in-memory cookie store and channel id service.
  // If both |cookie_store| and |channel_id_service| are NULL, CookieStore and
  // ChannelIDService will be disabled for this context.
  // If |cookie_store| is not NULL and |channel_id_service| is NULL,
  // only ChannelIdService is disabled for this context.
  // Note that a persistent cookie store should not be used with an in-memory
  // channel id service, and one cookie store should not be shared between
  // multiple channel-id stores (or used both with and without a channel id
  // store).
  void SetCookieAndChannelIdStores(
      std::unique_ptr<CookieStore> cookie_store,
      std::unique_ptr<ChannelIDService> channel_id_service);

  // Sets the task runner used to perform file operations. If not set, one will
  // be created.
  void SetFileTaskRunner(
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner);

  // Note that if SDCH is enabled without a policy object observing
  // the SDCH manager and handling at least Get-Dictionary events, the
  // result will be "Content-Encoding: sdch" advertisements, but no
  // dictionaries fetches and no specific dictionaries advertised.
  // SdchOwner in net/sdch/sdch_owner.h is a simple policy object.
  void set_sdch_enabled(bool enable) { sdch_enabled_ = enable; }

  // Sets a specific HttpServerProperties for use in the
  // URLRequestContext rather than creating a default HttpServerPropertiesImpl.
  void SetHttpServerProperties(
      std::unique_ptr<HttpServerProperties> http_server_properties);

  std::unique_ptr<URLRequestContext> Build();

 private:
  std::string accept_language_;
  std::string user_agent_;
  // Include support for data:// requests.
  bool data_enabled_;
#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
  // Include support for file:// requests.
  bool file_enabled_;
#endif
#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
  // Include support for ftp:// requests.
  bool ftp_enabled_;
#endif
  bool http_cache_enabled_;
  bool throttling_enabled_;
  bool sdch_enabled_;
  bool cookie_store_set_by_client_;

  scoped_refptr<base::SingleThreadTaskRunner> file_task_runner_;
  HttpCacheParams http_cache_params_;
  HttpNetworkSessionParams http_network_session_params_;
  base::FilePath transport_security_persister_path_;
  NetLog* net_log_;
  std::unique_ptr<HostResolver> host_resolver_;
  std::unique_ptr<ChannelIDService> channel_id_service_;
  std::unique_ptr<ProxyConfigService> proxy_config_service_;
  std::unique_ptr<ProxyService> proxy_service_;
  std::unique_ptr<NetworkDelegate> network_delegate_;
  std::unique_ptr<ProxyDelegate> proxy_delegate_;
  std::unique_ptr<CookieStore> cookie_store_;
  std::unique_ptr<HttpAuthHandlerFactory> http_auth_handler_factory_;
  std::unique_ptr<CertVerifier> cert_verifier_;
  std::unique_ptr<CTVerifier> ct_verifier_;
  std::vector<std::unique_ptr<URLRequestInterceptor>> url_request_interceptors_;
  std::unique_ptr<HttpServerProperties> http_server_properties_;
  std::map<std::string, std::unique_ptr<URLRequestJobFactory::ProtocolHandler>>
      protocol_handlers_;
  // SocketPerformanceWatcherFactory to be used by this context builder.
  // Not owned by the context builder. Once it is set to a non-null value, it
  // is guaranteed to be non-null during the lifetime of |this|.
  SocketPerformanceWatcherFactory* socket_performance_watcher_factory_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestContextBuilder);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_H_
