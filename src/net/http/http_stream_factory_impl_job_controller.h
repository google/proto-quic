// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_CONTROLLER_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_CONTROLLER_H_

#include <memory>

#include "net/base/host_port_pair.h"
#include "net/base/privacy_mode.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_request.h"

namespace net {

class NetLogWithSource;

// HttpStreamFactoryImpl::JobController manages Request and Job(s).
class HttpStreamFactoryImpl::JobController
    : public HttpStreamFactoryImpl::Job::Delegate,
      public HttpStreamFactoryImpl::Request::Helper {
 public:
  JobController(HttpStreamFactoryImpl* factory,
                HttpStreamRequest::Delegate* delegate,
                HttpNetworkSession* session,
                JobFactory* job_factory,
                const HttpRequestInfo& request_info,
                bool is_preconnect,
                bool enable_ip_based_pooling,
                bool enable_alternative_services);

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
                 const NetLogWithSource& source_net_log,
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
  int RestartTunnelWithProxyAuth() override;

  // Called when the priority of transaction changes.
  void SetPriority(RequestPriority priority) override;

  // From HttpStreamFactoryImpl::Job::Delegate.
  // Invoked when |job| has an HttpStream ready.
  void OnStreamReady(Job* job, const SSLConfig& used_ssl_config) override;

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
                                  std::unique_ptr<HttpStream> stream) override;

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

  bool OnInitConnection(const ProxyInfo& proxy_info) override;

  void OnResolveProxyComplete(
      Job* job,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::StreamType stream_type) override;

  // Invoked to notify the Request and Factory of the readiness of new
  // SPDY session.
  void OnNewSpdySessionReady(Job* job,
                             const base::WeakPtr<SpdySession>& spdy_session,
                             bool direct) override;

  // Invoked when the |job| finishes pre-connecting sockets.
  void OnPreconnectsComplete(Job* job) override;

  // Invoked to record connection attempts made by the socket layer to
  // Request if |job| is associated with Request.
  void AddConnectionAttemptsToRequest(
      Job* job,
      const ConnectionAttempts& attempts) override;

  // Invoked when |job| finishes initiating a connection.
  // Resume the other job if there's an error raised.
  void OnConnectionInitialized(Job* job, int rv) override;

  // Return false if |job| can advance to the next state. Otherwise, |job|
  // will wait for Job::Resume() to be called before advancing.
  bool ShouldWait(Job* job) override;

  // Called when |job| determines the appropriate |spdy_session_key| for the
  // Request. Note that this does not mean that SPDY is necessarily supported
  // for this SpdySessionKey, since we may need to wait for NPN to complete
  // before knowing if SPDY is available.
  void SetSpdySessionKey(Job* job,
                         const SpdySessionKey& spdy_session_key) override;

  // Remove session from the SpdySessionRequestMap.
  void RemoveRequestFromSpdySessionRequestMapForJob(Job* job) override;

  const NetLogWithSource* GetNetLog() const override;

  void MaybeSetWaitTimeForMainJob(const base::TimeDelta& delay) override;

  WebSocketHandshakeStreamBase::CreateHelper*
  websocket_handshake_stream_create_helper() override;

  bool is_preconnect() const { return is_preconnect_; }

  // Returns true if |this| has a pending request that is not completed.
  bool HasPendingRequest() const { return request_ != nullptr; }

  // Returns true if |this| has a pending main job that is not completed.
  bool HasPendingMainJob() const;

  // Returns true if |this| has a pending alternative job that is not completed.
  bool HasPendingAltJob() const;

  // TODO(xunjieli): Added to investigate crbug.com/711721. Remove when no
  // longer needed.
  void LogHistograms() const;

  // Returns the estimated memory usage in bytes.
  size_t EstimateMemoryUsage() const;

 private:
  friend class JobControllerPeer;

  // Creates Job(s) for |request_|. Job(s) will be owned by |this|.
  void CreateJobs(const HttpRequestInfo& request_info,
                  RequestPriority priority,
                  const SSLConfig& server_ssl_config,
                  const SSLConfig& proxy_ssl_config,
                  HttpStreamRequest::Delegate* delegate,
                  HttpStreamRequest::StreamType stream_type);

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

  // Invoked when the orphaned |job| finishes.
  void OnOrphanedJobComplete(const Job* job);

  // Called when a Job succeeds.
  void OnJobSucceeded(Job* job);

  // Marks completion of the |request_|.
  void MarkRequestComplete(bool was_alpn_negotiated,
                           NextProto negotiated_protocol,
                           bool using_spdy);

  // Must be called when the alternative job fails. |net_error| is the net error
  // of the failed alternative job.
  void OnAlternativeJobFailed(int net_error);

  // Called to report to http_server_properties to mark alternative service
  // broken.
  void ReportBrokenAlternativeService();

  void MaybeNotifyFactoryOfCompletion();

  // Called to resume the main job with delay. Main job is resumed only when
  // |alternative_job_| has failed or |main_job_wait_time_| elapsed.
  void MaybeResumeMainJob(Job* job, const base::TimeDelta& delay);

  // Posts a task to resume the main job after |delay|.
  void ResumeMainJobLater(const base::TimeDelta& delay);

  // Resumes the main job immediately.
  void ResumeMainJob();

  AlternativeServiceInfo GetAlternativeServiceInfoFor(
      const HttpRequestInfo& request_info,
      HttpStreamRequest::Delegate* delegate,
      HttpStreamRequest::StreamType stream_type);

  AlternativeServiceInfo GetAlternativeServiceInfoInternal(
      const HttpRequestInfo& request_info,
      HttpStreamRequest::Delegate* delegate,
      HttpStreamRequest::StreamType stream_type);

  // Remove session from the SpdySessionRequestMap.
  void RemoveRequestFromSpdySessionRequestMap();

  // Returns true if the |request_| can be fetched via an alternative
  // proxy server, and sets |alternative_proxy_server| to the available
  // alternative proxy server. |alternative_proxy_server| should not be null,
  // and is owned by the caller.
  bool ShouldCreateAlternativeProxyServerJob(
      Job* job,
      const ProxyInfo& proxy_info_,
      const GURL& url,
      ProxyServer* alternative_proxy_server) const;

  // Records histogram metrics for the usage of alternative protocol. Must be
  // called when |job| has succeeded and the other job will be orphaned.
  void ReportAlternateProtocolUsage(Job* job) const;

  // Starts the |alternative_job_|.
  void StartAlternativeProxyServerJob();

  // Returns whether |job| is an orphaned job.
  bool IsJobOrphaned(Job* job) const;

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
  const bool is_preconnect_;

  // Enable pooling to a SpdySession with matching IP and certificate even if
  // the SpdySessionKey is different.
  const bool enable_ip_based_pooling_;

  // Enable using alternative services for the request.
  const bool enable_alternative_services_;

  // |main_job_| is a job waiting to see if |alternative_job_| can reuse a
  // connection. If |alternative_job_| is unable to do so, |this| will notify
  // |main_job_| to proceed and then race the two jobs.
  std::unique_ptr<Job> main_job_;
  std::unique_ptr<Job> alternative_job_;

  // Net error code of the failed alternative job. Set to OK by default.
  int alternative_job_net_error_;

  // Either and only one of these records failed alternative service/proxy
  // server that |alternative_job_| uses.
  AlternativeService failed_alternative_service_;
  ProxyServer failed_alternative_proxy_server_;

  // True if a Job has ever been bound to the |request_|.
  bool job_bound_;

  // True if the main job has to wait for the alternative job: i.e., the main
  // job must not create a connection until it is resumed.
  bool main_job_is_blocked_;

  // True if the main job was blocked and has been resumed in ResumeMainJob().
  bool main_job_is_resumed_;

  // Waiting time for the main job before it is resumed.
  base::TimeDelta main_job_wait_time_;

  // At the point where a Job is irrevocably tied to |request_|, we set this.
  // It will be nulled when the |request_| is finished.
  Job* bound_job_;

  // True if an alternative proxy server job can be started to fetch |request_|.
  bool can_start_alternative_proxy_job_;

  // Privacy mode that should be used for fetching the resource.
  PrivacyMode privacy_mode_;

  const NetLogWithSource net_log_;

  base::WeakPtrFactory<JobController> ptr_factory_;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_CONTROLLER_H_
