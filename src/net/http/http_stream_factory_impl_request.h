// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_IMPL_REQUEST_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_IMPL_REQUEST_H_

#include <memory>
#include <set>

#include "base/macros.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/log/net_log.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session_key.h"
#include "net/ssl/ssl_failure_state.h"
#include "url/gurl.h"

namespace net {

class BidirectionalStreamImpl;
class ClientSocketHandle;
class HttpStream;
class SpdySession;

class HttpStreamFactoryImpl::Request : public HttpStreamRequest {
 public:
  Request(const GURL& url,
          HttpStreamFactoryImpl* factory,
          HttpStreamRequest::Delegate* delegate,
          WebSocketHandshakeStreamBase::CreateHelper*
              websocket_handshake_stream_create_helper,
          const BoundNetLog& net_log,
          StreamType stream_type);

  ~Request() override;

  // The GURL from the HttpRequestInfo the started the Request.
  const GURL& url() const { return url_; }

  const BoundNetLog& net_log() const { return net_log_; }

  // Called when the Job determines the appropriate |spdy_session_key| for the
  // Request. Note that this does not mean that SPDY is necessarily supported
  // for this SpdySessionKey, since we may need to wait for NPN to complete
  // before knowing if SPDY is available.
  void SetSpdySessionKey(const SpdySessionKey& spdy_session_key);
  bool HasSpdySessionKey() const;

  // Attaches |job| to this request. Does not mean that Request will use |job|,
  // but Request will own |job|.
  void AttachJob(HttpStreamFactoryImpl::Job* job);

  // Marks completion of the request. Must be called before OnStreamReady().
  void Complete(bool was_npn_negotiated,
                NextProto protocol_negotiated,
                bool using_spdy);

  // If this Request has a |spdy_session_key_|, remove this session from the
  // SpdySessionRequestMap.
  void RemoveRequestFromSpdySessionRequestMap();

  // Called by an attached Job if it sets up a SpdySession.
  // |stream| is null when |stream_type| is HttpStreamRequest::HTTP_STREAM.
  // |bidirectional_stream_spdy_impl| is null when |stream_type| is
  // HttpStreamRequest::BIDIRECTIONAL_STREAM.
  void OnNewSpdySessionReady(
      Job* job,
      std::unique_ptr<HttpStream> stream,
      std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_spdy_impl,
      const base::WeakPtr<SpdySession>& spdy_session,
      bool direct);

  // Called by an attached Job to record connection attempts made by the socket
  // layer for this stream request.
  void AddConnectionAttempts(const ConnectionAttempts& attempts);

  WebSocketHandshakeStreamBase::CreateHelper*
  websocket_handshake_stream_create_helper() {
    return websocket_handshake_stream_create_helper_;
  }

  // HttpStreamRequest::Delegate methods which we implement. Note we don't
  // actually subclass HttpStreamRequest::Delegate.

  void OnStreamReady(Job* job,
                     const SSLConfig& used_ssl_config,
                     const ProxyInfo& used_proxy_info,
                     HttpStream* stream);
  void OnBidirectionalStreamImplReady(Job* job,
                                      const SSLConfig& used_ssl_config,
                                      const ProxyInfo& used_proxy_info,
                                      BidirectionalStreamImpl* stream);

  void OnWebSocketHandshakeStreamReady(Job* job,
                                       const SSLConfig& used_ssl_config,
                                       const ProxyInfo& used_proxy_info,
                                       WebSocketHandshakeStreamBase* stream);
  void OnStreamFailed(Job* job,
                      int status,
                      const SSLConfig& used_ssl_config,
                      SSLFailureState ssl_failure_state);
  void OnCertificateError(Job* job,
                          int status,
                          const SSLConfig& used_ssl_config,
                          const SSLInfo& ssl_info);
  void OnNeedsProxyAuth(Job* job,
                        const HttpResponseInfo& proxy_response,
                        const SSLConfig& used_ssl_config,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller);
  void OnNeedsClientAuth(Job* job,
                         const SSLConfig& used_ssl_config,
                         SSLCertRequestInfo* cert_info);
  void OnHttpsProxyTunnelResponse(
      Job *job,
      const HttpResponseInfo& response_info,
      const SSLConfig& used_ssl_config,
      const ProxyInfo& used_proxy_info,
      HttpStream* stream);

  // HttpStreamRequest methods.

  int RestartTunnelWithProxyAuth(const AuthCredentials& credentials) override;
  void SetPriority(RequestPriority priority) override;
  LoadState GetLoadState() const override;
  bool was_npn_negotiated() const override;
  NextProto protocol_negotiated() const override;
  bool using_spdy() const override;
  const ConnectionAttempts& connection_attempts() const override;
  HttpStreamRequest::StreamType stream_type() const { return stream_type_; }

 private:
  // Used to bind |job| to the request and orphan all other jobs in |jobs_|.
  void BindJob(Job* job);

  // Used to orphan all jobs in |jobs_|.
  void OrphanJobs();

  // Used to cancel all jobs in |jobs_|.
  void CancelJobs();

  // Called when a Job succeeds.
  void OnJobSucceeded(Job* job);

  const GURL url_;
  HttpStreamFactoryImpl* const factory_;
  WebSocketHandshakeStreamBase::CreateHelper* const
      websocket_handshake_stream_create_helper_;
  HttpStreamRequest::Delegate* const delegate_;
  const BoundNetLog net_log_;

  // At the point where Job is irrevocably tied to the Request, we set this.
  std::unique_ptr<Job> bound_job_;
  std::set<HttpStreamFactoryImpl::Job*> jobs_;
  std::unique_ptr<const SpdySessionKey> spdy_session_key_;

  bool completed_;
  bool was_npn_negotiated_;
  // Protocol negotiated with the server.
  NextProto protocol_negotiated_;
  bool using_spdy_;
  ConnectionAttempts connection_attempts_;

  const HttpStreamRequest::StreamType stream_type_;
  DISALLOW_COPY_AND_ASSIGN(Request);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_REQUEST_H_
