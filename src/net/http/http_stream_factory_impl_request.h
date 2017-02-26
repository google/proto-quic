// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_IMPL_REQUEST_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_IMPL_REQUEST_H_

#include <memory>
#include <set>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session_key.h"
#include "url/gurl.h"

namespace net {

class BidirectionalStreamImpl;
class HttpStream;

class HttpStreamFactoryImpl::Request : public HttpStreamRequest {
 public:
  class NET_EXPORT_PRIVATE Helper {
   public:
    virtual ~Helper() {}

    // Returns the LoadState for Request.
    virtual LoadState GetLoadState() const = 0;

    // Called when Request is destructed.
    virtual void OnRequestComplete() = 0;

    // Called to resume the HttpStream creation process when necessary
    // Proxy authentication credentials are collected.
    virtual int RestartTunnelWithProxyAuth() = 0;

    // Called when the priority of transaction changes.
    virtual void SetPriority(RequestPriority priority) = 0;
  };

  // Request will notify |job_controller| when it's destructed.
  // Thus |job_controller| is valid for the lifetime of the |this| Request.
  Request(const GURL& url,
          Helper* helper,
          HttpStreamRequest::Delegate* delegate,
          WebSocketHandshakeStreamBase::CreateHelper*
              websocket_handshake_stream_create_helper,
          const NetLogWithSource& net_log,
          StreamType stream_type);

  ~Request() override;

  // The GURL from the HttpRequestInfo the started the Request.
  const GURL& url() const { return url_; }

  const NetLogWithSource& net_log() const { return net_log_; }

  // Called when the |helper_| determines the appropriate |spdy_session_key|
  // for the Request. Note that this does not mean that SPDY is necessarily
  // supported for this SpdySessionKey, since we may need to wait for NPN to
  // complete before knowing if SPDY is available.
  void SetSpdySessionKey(const SpdySessionKey& spdy_session_key);
  bool HasSpdySessionKey() const;

  // Marks completion of the request. Must be called before OnStreamReady().
  void Complete(bool was_alpn_negotiated,
                NextProto negotiated_protocol,
                bool using_spdy);

  void ResetSpdySessionKey();

  // Called by |helper_| to record connection attempts made by the socket
  // layer in an attached Job for this stream request.
  void AddConnectionAttempts(const ConnectionAttempts& attempts);

  WebSocketHandshakeStreamBase::CreateHelper*
  websocket_handshake_stream_create_helper() {
    return websocket_handshake_stream_create_helper_;
  }

  // HttpStreamRequest::Delegate methods which we implement. Note we don't
  // actually subclass HttpStreamRequest::Delegate.

  void OnStreamReady(const SSLConfig& used_ssl_config,
                     const ProxyInfo& used_proxy_info,
                     HttpStream* stream);
  void OnBidirectionalStreamImplReady(const SSLConfig& used_ssl_config,
                                      const ProxyInfo& used_proxy_info,
                                      BidirectionalStreamImpl* stream);

  void OnWebSocketHandshakeStreamReady(const SSLConfig& used_ssl_config,
                                       const ProxyInfo& used_proxy_info,
                                       WebSocketHandshakeStreamBase* stream);
  void OnStreamFailed(int status, const SSLConfig& used_ssl_config);
  void OnCertificateError(int status,
                          const SSLConfig& used_ssl_config,
                          const SSLInfo& ssl_info);
  void OnNeedsProxyAuth(const HttpResponseInfo& proxy_response,
                        const SSLConfig& used_ssl_config,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller);
  void OnNeedsClientAuth(const SSLConfig& used_ssl_config,
                         SSLCertRequestInfo* cert_info);
  void OnHttpsProxyTunnelResponse(
      const HttpResponseInfo& response_info,
      const SSLConfig& used_ssl_config,
      const ProxyInfo& used_proxy_info,
      HttpStream* stream);

  // HttpStreamRequest methods.

  int RestartTunnelWithProxyAuth() override;
  void SetPriority(RequestPriority priority) override;
  LoadState GetLoadState() const override;
  bool was_alpn_negotiated() const override;
  NextProto negotiated_protocol() const override;
  bool using_spdy() const override;
  const ConnectionAttempts& connection_attempts() const override;
  HttpStreamRequest::StreamType stream_type() const { return stream_type_; }
  const SpdySessionKey* spdy_session_key() const {
    return spdy_session_key_.get();
  }

 private:
  const GURL url_;

  // Unowned. The helper must outlive this request.
  Helper* helper_;

  WebSocketHandshakeStreamBase::CreateHelper* const
      websocket_handshake_stream_create_helper_;
  HttpStreamRequest::Delegate* const delegate_;
  const NetLogWithSource net_log_;

  std::unique_ptr<const SpdySessionKey> spdy_session_key_;

  bool completed_;
  bool was_alpn_negotiated_;
  // Protocol negotiated with the server.
  NextProto negotiated_protocol_;
  bool using_spdy_;
  ConnectionAttempts connection_attempts_;

  const HttpStreamRequest::StreamType stream_type_;
  DISALLOW_COPY_AND_ASSIGN(Request);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_REQUEST_H_
