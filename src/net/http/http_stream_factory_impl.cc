// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl.h"

#include <string>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_job_controller.h"
#include "net/http/http_stream_factory_impl_request.h"
#include "net/http/transport_security_state.h"
#include "net/proxy/proxy_info.h"
#include "net/quic/core/quic_server_id.h"
#include "net/spdy/bidirectional_stream_spdy_impl.h"
#include "net/spdy/spdy_http_stream.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {
// Default JobFactory for creating HttpStreamFactoryImpl::Jobs.
class DefaultJobFactory : public HttpStreamFactoryImpl::JobFactory {
 public:
  DefaultJobFactory() {}

  ~DefaultJobFactory() override {}

  HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      NetLog* net_log) override {
    return new HttpStreamFactoryImpl::Job(
        delegate, job_type, session, request_info, priority, server_ssl_config,
        proxy_ssl_config, destination, origin_url, net_log);
  }

  HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      AlternativeService alternative_service,
      NetLog* net_log) override {
    return new HttpStreamFactoryImpl::Job(
        delegate, job_type, session, request_info, priority, server_ssl_config,
        proxy_ssl_config, destination, origin_url, alternative_service,
        ProxyServer(), net_log);
  }

  HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      const ProxyServer& alternative_proxy_server,
      NetLog* net_log) override {
    return new HttpStreamFactoryImpl::Job(
        delegate, job_type, session, request_info, priority, server_ssl_config,
        proxy_ssl_config, destination, origin_url, AlternativeService(),
        alternative_proxy_server, net_log);
  }
};

// Returns true if only one preconnect to proxy servers is allowed via field
// trial.
bool AllowOnlyOnePreconnectToProxyServers() {
  return base::StartsWith(base::FieldTrialList::FindFullName(
                              "NetAllowOnlyOnePreconnectToProxyServers"),
                          "Enabled", base::CompareCase::INSENSITIVE_ASCII);
}

}  // anonymous namespace

HttpStreamFactoryImpl::HttpStreamFactoryImpl(HttpNetworkSession* session,
                                             bool for_websockets)
    : session_(session),
      job_factory_(new DefaultJobFactory()),
      for_websockets_(for_websockets),
      allow_only_one_preconnect_to_proxy_servers_(
          AllowOnlyOnePreconnectToProxyServers()) {}

HttpStreamFactoryImpl::~HttpStreamFactoryImpl() {
  DCHECK(request_map_.empty());
  DCHECK(spdy_session_request_map_.empty());
}

HttpStreamRequest* HttpStreamFactoryImpl::RequestStream(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::Delegate* delegate,
    const NetLogWithSource& net_log) {
  DCHECK(!for_websockets_);
  return RequestStreamInternal(request_info, priority, server_ssl_config,
                               proxy_ssl_config, delegate, nullptr,
                               HttpStreamRequest::HTTP_STREAM, net_log);
}

HttpStreamRequest* HttpStreamFactoryImpl::RequestWebSocketHandshakeStream(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper* create_helper,
    const NetLogWithSource& net_log) {
  DCHECK(for_websockets_);
  DCHECK(create_helper);
  return RequestStreamInternal(request_info, priority, server_ssl_config,
                               proxy_ssl_config, delegate, create_helper,
                               HttpStreamRequest::HTTP_STREAM, net_log);
}

HttpStreamRequest* HttpStreamFactoryImpl::RequestBidirectionalStreamImpl(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::Delegate* delegate,
    const NetLogWithSource& net_log) {
  DCHECK(!for_websockets_);
  DCHECK(request_info.url.SchemeIs(url::kHttpsScheme));

  return RequestStreamInternal(
      request_info, priority, server_ssl_config, proxy_ssl_config, delegate,
      nullptr, HttpStreamRequest::BIDIRECTIONAL_STREAM, net_log);
}

HttpStreamRequest* HttpStreamFactoryImpl::RequestStreamInternal(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    HttpStreamRequest::StreamType stream_type,
    const NetLogWithSource& net_log) {
  JobController* job_controller =
      new JobController(this, delegate, session_, job_factory_.get());
  job_controller_set_.insert(base::WrapUnique(job_controller));

  Request* request = job_controller->Start(
      request_info, delegate, websocket_handshake_stream_create_helper, net_log,
      stream_type, priority, server_ssl_config, proxy_ssl_config);

  return request;
}

void HttpStreamFactoryImpl::PreconnectStreams(
    int num_streams,
    const HttpRequestInfo& request_info) {
  SSLConfig server_ssl_config;
  SSLConfig proxy_ssl_config;
  session_->GetSSLConfig(request_info, &server_ssl_config, &proxy_ssl_config);
  // All preconnects should perform EV certificate verification.
  server_ssl_config.verify_ev_cert = true;
  proxy_ssl_config.verify_ev_cert = true;

  DCHECK(!for_websockets_);

  JobController* job_controller =
      new JobController(this, nullptr, session_, job_factory_.get());
  job_controller_set_.insert(base::WrapUnique(job_controller));
  job_controller->Preconnect(num_streams, request_info, server_ssl_config,
                             proxy_ssl_config);
}

const HostMappingRules* HttpStreamFactoryImpl::GetHostMappingRules() const {
  return session_->params().host_mapping_rules;
}

void HttpStreamFactoryImpl::OnNewSpdySessionReady(
    const base::WeakPtr<SpdySession>& spdy_session,
    bool direct,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    bool was_alpn_negotiated,
    NextProto negotiated_protocol,
    bool using_spdy,
    const NetLogWithSource& net_log) {
  while (true) {
    if (!spdy_session)
      break;
    const SpdySessionKey& spdy_session_key = spdy_session->spdy_session_key();
    // Each iteration may empty out the RequestSet for |spdy_session_key| in
    // |spdy_session_request_map_|. So each time, check for RequestSet and use
    // the first one.
    //
    // TODO(willchan): If it's important, switch RequestSet out for a FIFO
    // queue (Order by priority first, then FIFO within same priority). Unclear
    // that it matters here.
    if (!base::ContainsKey(spdy_session_request_map_, spdy_session_key))
      break;
    Request* request = *spdy_session_request_map_[spdy_session_key].begin();
    request->Complete(was_alpn_negotiated, negotiated_protocol, using_spdy);
    if (for_websockets_) {
      // TODO(ricea): Restore this code path when WebSocket over SPDY
      // implementation is ready.
      NOTREACHED();
    } else if (request->stream_type() ==
               HttpStreamRequest::BIDIRECTIONAL_STREAM) {
      request->OnBidirectionalStreamImplReady(
          used_ssl_config, used_proxy_info,
          new BidirectionalStreamSpdyImpl(spdy_session));
    } else {
      bool use_relative_url =
          direct || request->url().SchemeIs(url::kHttpsScheme);
      request->OnStreamReady(
          used_ssl_config, used_proxy_info,
          new SpdyHttpStream(spdy_session, use_relative_url));
    }
  }
  // TODO(mbelshe): Alert other valid requests.
}

void HttpStreamFactoryImpl::OnJobControllerComplete(JobController* controller) {
  for (auto it = job_controller_set_.begin(); it != job_controller_set_.end();
       ++it) {
    if (it->get() == controller) {
      job_controller_set_.erase(it);
      return;
    }
  }
  NOTREACHED();
}

bool HttpStreamFactoryImpl::OnInitConnection(const JobController& controller,
                                             const ProxyInfo& proxy_info) {
  if (!controller.is_preconnect()) {
    // Connection initialization can be skipped only for the preconnect jobs.
    return false;
  }

  if (!allow_only_one_preconnect_to_proxy_servers_ ||
      !ProxyServerSupportsPriorities(proxy_info)) {
    return false;
  }

  if (base::ContainsKey(preconnecting_proxy_servers_,
                        proxy_info.proxy_server())) {
    UMA_HISTOGRAM_EXACT_LINEAR("Net.PreconnectSkippedToProxyServers", 1, 2);
    // Skip preconnect to the proxy server since we are already preconnecting
    // (probably via some other job).
    return true;
  }

  // Add the proxy server to the set of preconnecting proxy servers.
  // The maximum size of |preconnecting_proxy_servers_|.
  static const size_t kMaxPreconnectingServerSize = 3;
  if (preconnecting_proxy_servers_.size() >= kMaxPreconnectingServerSize) {
    // Erase the first entry. A better approach (at the cost of higher memory
    // overhead) may be to erase the least recently used entry.
    preconnecting_proxy_servers_.erase(preconnecting_proxy_servers_.begin());
  }

  preconnecting_proxy_servers_.insert(proxy_info.proxy_server());
  DCHECK_GE(kMaxPreconnectingServerSize, preconnecting_proxy_servers_.size());
  // The first preconnect should be allowed.
  return false;
}

void HttpStreamFactoryImpl::OnStreamReady(const ProxyInfo& proxy_info) {
  if (proxy_info.is_empty())
    return;
  preconnecting_proxy_servers_.erase(proxy_info.proxy_server());
}

bool HttpStreamFactoryImpl::ProxyServerSupportsPriorities(
    const ProxyInfo& proxy_info) const {
  if (proxy_info.is_empty() || !proxy_info.proxy_server().is_valid())
    return false;

  if (!proxy_info.proxy_server().is_https())
    return false;

  HostPortPair host_port_pair = proxy_info.proxy_server().host_port_pair();
  DCHECK(!host_port_pair.IsEmpty());

  url::SchemeHostPort scheme_host_port("https", host_port_pair.host(),
                                       host_port_pair.port());

  return session_->http_server_properties()->SupportsRequestPriority(
      scheme_host_port);
}

}  // namespace net
