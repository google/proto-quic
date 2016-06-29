// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_request.h"

#include "base/callback.h"
#include "base/logging.h"
#include "base/stl_util.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_session.h"

namespace net {

HttpStreamFactoryImpl::Request::Request(
    const GURL& url,
    Helper* helper,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    const BoundNetLog& net_log,
    StreamType stream_type)
    : url_(url),
      helper_(helper),
      websocket_handshake_stream_create_helper_(
          websocket_handshake_stream_create_helper),
      delegate_(delegate),
      net_log_(net_log),
      completed_(false),
      was_npn_negotiated_(false),
      protocol_negotiated_(kProtoUnknown),
      using_spdy_(false),
      stream_type_(stream_type) {
  DCHECK(delegate_);

  net_log_.BeginEvent(NetLog::TYPE_HTTP_STREAM_REQUEST);
}

HttpStreamFactoryImpl::Request::~Request() {
  net_log_.EndEvent(NetLog::TYPE_HTTP_STREAM_REQUEST);
  helper_->OnRequestComplete();
}

void HttpStreamFactoryImpl::Request::SetSpdySessionKey(
    const SpdySessionKey& spdy_session_key) {
  spdy_session_key_.reset(new SpdySessionKey(spdy_session_key));
}

void HttpStreamFactoryImpl::Request::Complete(bool was_npn_negotiated,
                                              NextProto protocol_negotiated,
                                              bool using_spdy) {
  DCHECK(!completed_);
  completed_ = true;
  was_npn_negotiated_ = was_npn_negotiated;
  protocol_negotiated_ = protocol_negotiated;
  using_spdy_ = using_spdy;
}

void HttpStreamFactoryImpl::Request::OnStreamReady(
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpStream* stream) {
  DCHECK(completed_);
  delegate_->OnStreamReady(used_ssl_config, used_proxy_info, stream);
}

void HttpStreamFactoryImpl::Request::OnBidirectionalStreamImplReady(
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    BidirectionalStreamImpl* stream_job) {
  DCHECK(completed_);
  delegate_->OnBidirectionalStreamImplReady(used_ssl_config, used_proxy_info,
                                            stream_job);
}

void HttpStreamFactoryImpl::Request::OnWebSocketHandshakeStreamReady(
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    WebSocketHandshakeStreamBase* stream) {
  DCHECK(completed_);
  delegate_->OnWebSocketHandshakeStreamReady(
      used_ssl_config, used_proxy_info, stream);
}

void HttpStreamFactoryImpl::Request::OnStreamFailed(
    int status,
    const SSLConfig& used_ssl_config) {
  delegate_->OnStreamFailed(status, used_ssl_config);
}

void HttpStreamFactoryImpl::Request::OnCertificateError(
    int status,
    const SSLConfig& used_ssl_config,
    const SSLInfo& ssl_info) {
  delegate_->OnCertificateError(status, used_ssl_config, ssl_info);
}

void HttpStreamFactoryImpl::Request::OnNeedsProxyAuth(
    const HttpResponseInfo& proxy_response,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  delegate_->OnNeedsProxyAuth(
      proxy_response, used_ssl_config, used_proxy_info, auth_controller);
}

void HttpStreamFactoryImpl::Request::OnNeedsClientAuth(
    const SSLConfig& used_ssl_config,
    SSLCertRequestInfo* cert_info) {
  delegate_->OnNeedsClientAuth(used_ssl_config, cert_info);
}

void HttpStreamFactoryImpl::Request::OnHttpsProxyTunnelResponse(
    const HttpResponseInfo& response_info,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpStream* stream) {
  delegate_->OnHttpsProxyTunnelResponse(
      response_info, used_ssl_config, used_proxy_info, stream);
}

int HttpStreamFactoryImpl::Request::RestartTunnelWithProxyAuth(
    const AuthCredentials& credentials) {
  return helper_->RestartTunnelWithProxyAuth(credentials);
}

void HttpStreamFactoryImpl::Request::SetPriority(RequestPriority priority) {
  helper_->SetPriority(priority);
}

LoadState HttpStreamFactoryImpl::Request::GetLoadState() const {
  return helper_->GetLoadState();
}

bool HttpStreamFactoryImpl::Request::was_npn_negotiated() const {
  DCHECK(completed_);
  return was_npn_negotiated_;
}

NextProto HttpStreamFactoryImpl::Request::protocol_negotiated()
    const {
  DCHECK(completed_);
  return protocol_negotiated_;
}

bool HttpStreamFactoryImpl::Request::using_spdy() const {
  DCHECK(completed_);
  return using_spdy_;
}

const ConnectionAttempts& HttpStreamFactoryImpl::Request::connection_attempts()
    const {
  return connection_attempts_;
}

void HttpStreamFactoryImpl::Request::ResetSpdySessionKey() {
  if (spdy_session_key_.get()) {
    spdy_session_key_.reset();
  }
}

bool HttpStreamFactoryImpl::Request::HasSpdySessionKey() const {
  return spdy_session_key_.get() != NULL;
}

void HttpStreamFactoryImpl::Request::AddConnectionAttempts(
    const ConnectionAttempts& attempts) {
  for (const auto& attempt : attempts)
    connection_attempts_.push_back(attempt);
}

}  // namespace net
