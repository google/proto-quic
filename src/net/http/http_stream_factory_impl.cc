// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl.h"

#include <string>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_job_controller.h"
#include "net/http/http_stream_factory_impl_request.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/quic/quic_server_id.h"
#include "net/spdy/bidirectional_stream_spdy_impl.h"
#include "net/spdy/spdy_http_stream.h"
#include "url/gurl.h"

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
        net_log);
  }
};
}  // anonymous namespace

HttpStreamFactoryImpl::HttpStreamFactoryImpl(HttpNetworkSession* session,
                                             bool for_websockets)
    : session_(session),
      job_factory_(new DefaultJobFactory()),
      for_websockets_(for_websockets) {}

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
          used_ssl_config, used_proxy_info,
          new BidirectionalStreamSpdyImpl(spdy_session));
    } else {
      bool use_relative_url = direct || request->url().SchemeIs("https");
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

}  // namespace net
