// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl.h"

#include <string>

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_request.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/quic/quic_server_id.h"
#include "net/spdy/bidirectional_stream_spdy_impl.h"
#include "net/spdy/spdy_http_stream.h"
#include "url/gurl.h"

namespace net {

HttpStreamFactoryImpl::HttpStreamFactoryImpl(HttpNetworkSession* session,
                                             bool for_websockets)
    : session_(session),
      for_websockets_(for_websockets) {}

HttpStreamFactoryImpl::~HttpStreamFactoryImpl() {
  DCHECK(request_map_.empty());
  DCHECK(spdy_session_request_map_.empty());

  std::set<const Job*> tmp_job_set;
  tmp_job_set.swap(orphaned_job_set_);
  STLDeleteContainerPointers(tmp_job_set.begin(), tmp_job_set.end());
  DCHECK(orphaned_job_set_.empty());

  tmp_job_set.clear();
  tmp_job_set.swap(preconnect_job_set_);
  STLDeleteContainerPointers(tmp_job_set.begin(), tmp_job_set.end());
  DCHECK(preconnect_job_set_.empty());
}

HttpStreamRequest* HttpStreamFactoryImpl::RequestStream(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::Delegate* delegate,
    const BoundNetLog& net_log) {
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
    const BoundNetLog& net_log) {
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
    const BoundNetLog& net_log) {
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
    const BoundNetLog& net_log) {
  Request* request = new Request(request_info.url, this, delegate,
                                 websocket_handshake_stream_create_helper,
                                 net_log, stream_type);
  HostPortPair destination(HostPortPair::FromURL(request_info.url));
  GURL origin_url = ApplyHostMappingRules(request_info.url, &destination);

  Job* job =
      new Job(this, session_, request_info, priority, server_ssl_config,
              proxy_ssl_config, destination, origin_url, net_log.net_log());
  request->AttachJob(job);

  const AlternativeService alternative_service =
      GetAlternativeServiceFor(request_info, delegate, stream_type);

  if (alternative_service.protocol != UNINITIALIZED_ALTERNATE_PROTOCOL) {
    // Never share connection with other jobs for FTP requests.
    DVLOG(1) << "Selected alternative service (host: "
             << alternative_service.host_port_pair().host()
             << " port: " << alternative_service.host_port_pair().port() << ")";

    DCHECK(!request_info.url.SchemeIs("ftp"));
    HostPortPair alternative_destination(alternative_service.host_port_pair());
    ignore_result(
        ApplyHostMappingRules(request_info.url, &alternative_destination));

    Job* alternative_job =
        new Job(this, session_, request_info, priority, server_ssl_config,
                proxy_ssl_config, alternative_destination, origin_url,
                alternative_service, net_log.net_log());
    request->AttachJob(alternative_job);

    job->WaitFor(alternative_job);
    // Make sure to wait until we call WaitFor(), before starting
    // |alternative_job|, otherwise |alternative_job| will not notify |job|
    // appropriately.
    alternative_job->Start(request);
  }

  // Even if |alternative_job| has already finished, it will not have notified
  // the request yet, since we defer that to the next iteration of the
  // MessageLoop, so starting |job| is always safe.
  job->Start(request);
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
  AlternativeService alternative_service = GetAlternativeServiceFor(
      request_info, nullptr, HttpStreamRequest::HTTP_STREAM);
  HostPortPair destination(HostPortPair::FromURL(request_info.url));
  GURL origin_url = ApplyHostMappingRules(request_info.url, &destination);
  if (alternative_service.protocol != UNINITIALIZED_ALTERNATE_PROTOCOL) {
    if (session_->params().quic_disable_preconnect_if_0rtt &&
        alternative_service.protocol == QUIC &&
        session_->quic_stream_factory()->ZeroRTTEnabledFor(QuicServerId(
            alternative_service.host_port_pair(), request_info.privacy_mode))) {
      return;
    }
    destination = alternative_service.host_port_pair();
    ignore_result(ApplyHostMappingRules(request_info.url, &destination));
  }
  // Due to how the socket pools handle priorities and idle sockets, only IDLE
  // priority currently makes sense for preconnects. The priority for
  // preconnects is currently ignored (see RequestSocketsForPool()), but could
  // be used at some point for proxy resolution or something.
  Job* job = new Job(this, session_, request_info, IDLE, server_ssl_config,
                     proxy_ssl_config, destination, origin_url,
                     alternative_service, session_->net_log());
  preconnect_job_set_.insert(job);
  job->Preconnect(num_streams);
}

const HostMappingRules* HttpStreamFactoryImpl::GetHostMappingRules() const {
  return session_->params().host_mapping_rules;
}

AlternativeService HttpStreamFactoryImpl::GetAlternativeServiceFor(
    const HttpRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  GURL original_url = request_info.url;

  if (original_url.SchemeIs("ftp"))
    return AlternativeService();

  url::SchemeHostPort origin(original_url);
  HttpServerProperties& http_server_properties =
      *session_->http_server_properties();
  const AlternativeServiceVector alternative_service_vector =
      http_server_properties.GetAlternativeServices(origin);
  if (alternative_service_vector.empty())
    return AlternativeService();

  bool quic_advertised = false;
  bool quic_all_broken = true;

  const bool enable_different_host =
      session_->params().enable_alternative_service_with_different_host;

  // First Alt-Svc that is not marked as broken.
  AlternativeService first_alternative_service;

  for (const AlternativeService& alternative_service :
       alternative_service_vector) {
    DCHECK(IsAlternateProtocolValid(alternative_service.protocol));
    if (!quic_advertised && alternative_service.protocol == QUIC)
      quic_advertised = true;
    if (http_server_properties.IsAlternativeServiceBroken(
            alternative_service)) {
      HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_BROKEN);
      continue;
    }

    if (origin.host() != alternative_service.host && !enable_different_host)
      continue;

    // Some shared unix systems may have user home directories (like
    // http://foo.com/~mike) which allow users to emit headers.  This is a bad
    // idea already, but with Alternate-Protocol, it provides the ability for a
    // single user on a multi-user system to hijack the alternate protocol.
    // These systems also enforce ports <1024 as restricted ports.  So don't
    // allow protocol upgrades to user-controllable ports.
    const int kUnrestrictedPort = 1024;
    if (!session_->params().enable_user_alternate_protocol_ports &&
        (alternative_service.port >= kUnrestrictedPort &&
         origin.port() < kUnrestrictedPort))
      continue;

    if (alternative_service.protocol >= NPN_SPDY_MINIMUM_VERSION &&
        alternative_service.protocol <= NPN_SPDY_MAXIMUM_VERSION) {
      if (!HttpStreamFactory::spdy_enabled())
        continue;

      // Cache this entry if we don't have a non-broken Alt-Svc yet.
      if (first_alternative_service.protocol ==
          UNINITIALIZED_ALTERNATE_PROTOCOL)
        first_alternative_service = alternative_service;
      continue;
    }

    DCHECK_EQ(QUIC, alternative_service.protocol);
    quic_all_broken = false;
    if (!session_->params().enable_quic)
      continue;

    if (!IsQuicWhitelistedForHost(origin.host()))
      continue;

    if (stream_type == HttpStreamRequest::BIDIRECTIONAL_STREAM &&
        session_->params().quic_disable_bidirectional_streams) {
      continue;
    }

    if (session_->quic_stream_factory()->IsQuicDisabled(
            alternative_service.port))
      continue;

    if (!original_url.SchemeIs("https"))
      continue;

    // Check whether there is an existing QUIC session to use for this origin.
    HostPortPair mapped_origin(origin.host(), origin.port());
    ignore_result(ApplyHostMappingRules(original_url, &mapped_origin));
    QuicServerId server_id(mapped_origin, request_info.privacy_mode);

    HostPortPair destination(alternative_service.host_port_pair());
    ignore_result(ApplyHostMappingRules(original_url, &destination));

    if (session_->quic_stream_factory()->CanUseExistingSession(server_id,
                                                               destination)) {
      return alternative_service;
    }

    // Cache this entry if we don't have a non-broken Alt-Svc yet.
    if (first_alternative_service.protocol == UNINITIALIZED_ALTERNATE_PROTOCOL)
      first_alternative_service = alternative_service;
  }

  // Ask delegate to mark QUIC as broken for the origin.
  if (quic_advertised && quic_all_broken && delegate != nullptr)
    delegate->OnQuicBroken();

  return first_alternative_service;
}

void HttpStreamFactoryImpl::OrphanJob(Job* job, const Request* request) {
  DCHECK(ContainsKey(request_map_, job));
  DCHECK_EQ(request_map_[job], request);
  DCHECK(!ContainsKey(orphaned_job_set_, job));

  request_map_.erase(job);

  orphaned_job_set_.insert(job);
  job->Orphan(request);
}

void HttpStreamFactoryImpl::OnNewSpdySessionReady(
    const base::WeakPtr<SpdySession>& spdy_session,
    bool direct,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    bool was_npn_negotiated,
    NextProto protocol_negotiated,
    bool using_spdy,
    const BoundNetLog& net_log) {
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
    if (!ContainsKey(spdy_session_request_map_, spdy_session_key))
      break;
    Request* request = *spdy_session_request_map_[spdy_session_key].begin();
    request->Complete(was_npn_negotiated, protocol_negotiated, using_spdy);
    if (for_websockets_) {
      // TODO(ricea): Restore this code path when WebSocket over SPDY
      // implementation is ready.
      NOTREACHED();
    } else if (request->stream_type() ==
               HttpStreamRequest::BIDIRECTIONAL_STREAM) {
      request->OnBidirectionalStreamImplReady(
          nullptr, used_ssl_config, used_proxy_info,
          new BidirectionalStreamSpdyImpl(spdy_session));
    } else {
      bool use_relative_url = direct || request->url().SchemeIs("https");
      request->OnStreamReady(
          nullptr, used_ssl_config, used_proxy_info,
          new SpdyHttpStream(spdy_session, use_relative_url));
    }
  }
  // TODO(mbelshe): Alert other valid requests.
}

void HttpStreamFactoryImpl::OnOrphanedJobComplete(const Job* job) {
  orphaned_job_set_.erase(job);
  delete job;
}

void HttpStreamFactoryImpl::OnPreconnectsComplete(const Job* job) {
  preconnect_job_set_.erase(job);
  delete job;
  OnPreconnectsCompleteInternal();
}

bool HttpStreamFactoryImpl::IsQuicWhitelistedForHost(const std::string& host) {
  bool whitelist_needed = false;
  for (QuicVersion version : session_->params().quic_supported_versions) {
    if (version <= QUIC_VERSION_30) {
      whitelist_needed = true;
      break;
    }
  }

  // The QUIC whitelist is not needed in QUIC versions after 30.
  if (!whitelist_needed)
    return true;

  if (session_->params().transport_security_state->IsGooglePinnedHost(host))
    return true;

  return ContainsKey(session_->params().quic_host_whitelist,
                     base::ToLowerASCII(host));
}

}  // namespace net
