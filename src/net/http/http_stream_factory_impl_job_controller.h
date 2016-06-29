// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_CONTROLLER_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_CONTROLLER_H_

#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_request.h"

namespace net {

// HttpStreamFactoryImpl::JobController manages Request and Job(s).
class HttpStreamFactoryImpl::JobController
    : public HttpStreamFactoryImpl::Job::Delegate,
      public HttpStreamFactoryImpl::Request::Helper {
 public:
  JobController(HttpStreamFactoryImpl* factory,
                HttpStreamRequest::Delegate* delegate,
                HttpNetworkSession* session,
                JobFactory* job_factory);

  ~JobController() override;

  bool for_websockets() override;

  // Used in tests only for verification purpose.
  const Job* main_job() const { return main_job_.get(); }
  const Job* alternative_job() const { return alternative_job_.get(); }

  GURL ApplyHostMappingRules(const GURL& url, HostPortPair* endpoint);

  // Methods below are called by HttpStreamFactoryImpl only.
  // Creates request and hands out to HttpStreamFactoryImpl, this will also
  // create Job(s) and start serving the created request.
  Request* Start(const HttpRequestInfo& request_info,
                 HttpStreamRequest::Delegate* delegate,
                 WebSocketHandshakeStreamBase::CreateHelper*
                     websocket_handshake_stream_create_helper,
                 const BoundNetLog& net_log,
                 HttpStreamRequest::StreamType stream_type,
                 RequestPriority priority,
                 const SSLConfig& server_ssl_config,
                 const SSLConfig& proxy_ssl_config);

  void Preconnect(int num_streams,
                  const HttpRequestInfo& request_info,
                  const SSLConfig& server_ssl_config,
                  const SSLConfig& proxy_ssl_config);

  // From HttpStreamFactoryImpl::Request::Helper.
  // Returns the LoadState for Request.
  LoadState GetLoadState() const override;

  // Called when Request is destructed. Job(s) associated with but not bound to
  // |request_| will be deleted. |request_| and |bound_job_| will be nulled if
  // ever set.
  void OnRequestComplete() override;

  // Called to resume the HttpStream creation process when necessary
  // Proxy authentication credentials are collected.
  int RestartTunnelWithProxyAuth(const AuthCredentials& credentials) override;

  // Called when the priority of transaction changes.
  void SetPriority(RequestPriority priority) override;

  // From HttpStreamFactoryImpl::Job::Delegate.
  // Invoked when |job| has an HttpStream ready.
  void OnStreamReady(Job* job,
                     const SSLConfig& used_ssl_config,
                     const ProxyInfo& used_proxy_info) override;

  // Invoked when |job| has a BidirectionalStream ready.
  void OnBidirectionalStreamImplReady(
      Job* job,
      const SSLConfig& used_ssl_config,
      const ProxyInfo& used_proxy_info) override;

  // Invoked when |job| has a WebSocketHandshakeStream ready.
  void OnWebSocketHandshakeStreamReady(
      Job* job,
      const SSLConfig& used_ssl_config,
      const ProxyInfo& used_proxy_info,
      WebSocketHandshakeStreamBase* stream) override;

  // Invoked when |job| fails to create a stream.
  void OnStreamFailed(Job* job,
                      int status,
                      const SSLConfig& used_ssl_config) override;

  // Invoked when |job| has a certificate error for the Request.
  void OnCertificateError(Job* job,
                          int status,
                          const SSLConfig& used_ssl_config,
                          const SSLInfo& ssl_info) override;

  // Invoked when |job| has a failure of the CONNECT request through an HTTPS
  // proxy.
  void OnHttpsProxyTunnelResponse(Job* job,
                                  const HttpResponseInfo& response_info,
                                  const SSLConfig& used_ssl_config,
                                  const ProxyInfo& used_proxy_info,
                                  HttpStream* stream) override;

  // Invoked when |job| raises failure for SSL Client Auth.
  void OnNeedsClientAuth(Job* job,
                         const SSLConfig& used_ssl_config,
                         SSLCertRequestInfo* cert_info) override;

  // Invoked when |job| needs proxy authentication.
  void OnNeedsProxyAuth(Job* job,
                        const HttpResponseInfo& proxy_response,
                        const SSLConfig& used_ssl_config,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller) override;

  // Invoked to notify the Request and Factory of the readiness of new
  // SPDY session.
  void OnNewSpdySessionReady(Job* job,
                             const base::WeakPtr<SpdySession>& spdy_session,
                             bool direct) override;

  // Invoked when the orphaned |job| finishes.
  void OnOrphanedJobComplete(const Job* job) override;

  // Invoked when the |job| finishes pre-connecting sockets.
  void OnPreconnectsComplete(Job* job) override;

  // Invoked to record connection attempts made by the socket layer to
  // Request if |job| is associated with Request.
  void AddConnectionAttemptsToRequest(
      Job* job,
      const ConnectionAttempts& attempts) override;

  // Called when |job| determines the appropriate |spdy_session_key| for the
  // Request. Note that this does not mean that SPDY is necessarily supported
  // for this SpdySessionKey, since we may need to wait for NPN to complete
  // before knowing if SPDY is available.
  void SetSpdySessionKey(Job* job,
                         const SpdySessionKey& spdy_session_key) override;

  // Remove session from the SpdySessionRequestMap.
  void RemoveRequestFromSpdySessionRequestMapForJob(Job* job) override;
  const BoundNetLog* GetNetLog(Job* job) const override;
  WebSocketHandshakeStreamBase::CreateHelper*
  websocket_handshake_stream_create_helper() override;

 private:
  FRIEND_TEST_ALL_PREFIXES(HttpStreamFactoryImplRequestTest, DelayMainJob);

  // Creates Job(s) for |request_|. Job(s) will be owned by |this|.
  void CreateJobs(const HttpRequestInfo& request_info,
                  RequestPriority priority,
                  const SSLConfig& server_ssl_config,
                  const SSLConfig& proxy_ssl_config,
                  HttpStreamRequest::Delegate* delegate,
                  HttpStreamRequest::StreamType stream_type,
                  const BoundNetLog& net_log);

  // Attaches |job| to |request_|. Does not mean that |request_| will use |job|.
  void AttachJob(Job* job);

  // Called to bind |job| to the |request_| and orphan all other jobs that are
  // still associated with |request_|.
  void BindJob(Job* job);

  // Called when |request_| is destructed.
  // Job(s) associated with but not bound to |request_| will be deleted.
  void CancelJobs();

  // Called after BindJob() to notify the unbound job that its result should be
  // ignored by JobController. The unbound job can be canceled or continue until
  // completion.
  void OrphanUnboundJob();

  // Called when a Job succeeds.
  void OnJobSucceeded(Job* job);

  // Marks completion of the |request_|.
  void MarkRequestComplete(bool was_npn_negotiated,
                           NextProto protocol_negotiated,
                           bool using_spdy);

  void MaybeNotifyFactoryOfCompletion();

  // Returns true if QUIC is whitelisted for |host|.
  bool IsQuicWhitelistedForHost(const std::string& host);

  AlternativeService GetAlternativeServiceFor(
      const HttpRequestInfo& request_info,
      HttpStreamRequest::Delegate* delegate,
      HttpStreamRequest::StreamType stream_type);

  AlternativeService GetAlternativeServiceForInternal(
      const HttpRequestInfo& request_info,
      HttpStreamRequest::Delegate* delegate,
      HttpStreamRequest::StreamType stream_type);

  // Remove session from the SpdySessionRequestMap.
  void RemoveRequestFromSpdySessionRequestMap();

  HttpStreamFactoryImpl* factory_;
  HttpNetworkSession* session_;
  JobFactory* job_factory_;

  // Request will be handed out to factory once created. This just keeps an
  // reference and is safe as |request_| will notify |this| JobController
  // when it's destructed by calling OnRequestComplete(), which nulls
  // |request_|.
  Request* request_;

  HttpStreamRequest::Delegate* const delegate_;

  // True if this JobController is used to preconnect streams.
  bool is_preconnect_;

  // |main_job_| is a job waiting to see if |alternative_job_| can reuse a
  // connection. If |alternative_job_| is unable to do so, |this| will notify
  // |main_job_| to proceed and then race the two jobs.
  std::unique_ptr<Job> main_job_;
  std::unique_ptr<Job> alternative_job_;

  // True if a Job has ever been bound to the |request_|.
  bool job_bound_;

  // At the point where a Job is irrevocably tied to |request_|, we set this.
  // It will be nulled when the |request_| is finished.
  Job* bound_job_;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_CONTROLLER_H_
