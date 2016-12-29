// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_H_

#include <memory>
#include <utility>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_controller.h"
#include "net/http/http_request_info.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/proxy_server.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/chromium/quic_stream_factory.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session_key.h"
#include "net/ssl/ssl_config_service.h"

namespace net {

class ClientSocketHandle;
class HttpAuthController;
class HttpNetworkSession;
class HttpStream;
class SpdySessionPool;
class NetLog;
struct SSLConfig;

// An HttpStreamRequestImpl exists for each stream which is in progress of being
// created for the StreamFactory.
class HttpStreamFactoryImpl::Job {
 public:
  // Delegate to report Job's status to Request and HttpStreamFactory.
  class NET_EXPORT_PRIVATE Delegate {
   public:
    virtual ~Delegate() {}

    // Invoked when |job| has an HttpStream ready.
    virtual void OnStreamReady(Job* job, const SSLConfig& used_ssl_config) = 0;

    // Invoked when |job| has a BidirectionalStream ready.
    virtual void OnBidirectionalStreamImplReady(
        Job* job,
        const SSLConfig& used_ssl_config,
        const ProxyInfo& used_proxy_info) = 0;

    // Invoked when |job| has a WebSocketHandshakeStream ready.
    virtual void OnWebSocketHandshakeStreamReady(
        Job* job,
        const SSLConfig& used_ssl_config,
        const ProxyInfo& used_proxy_info,
        WebSocketHandshakeStreamBase* stream) = 0;

    // Invoked when |job| fails to create a stream.
    virtual void OnStreamFailed(Job* job,
                                int status,
                                const SSLConfig& used_ssl_config) = 0;

    // Invoked when |job| has a certificate error for the Request.
    virtual void OnCertificateError(Job* job,
                                    int status,
                                    const SSLConfig& used_ssl_config,
                                    const SSLInfo& ssl_info) = 0;

    // Invoked when |job| has a failure of the CONNECT request through an HTTPS
    // proxy.
    virtual void OnHttpsProxyTunnelResponse(
        Job* job,
        const HttpResponseInfo& response_info,
        const SSLConfig& used_ssl_config,
        const ProxyInfo& used_proxy_info,
        HttpStream* stream) = 0;

    // Invoked when |job| raises failure for SSL Client Auth.
    virtual void OnNeedsClientAuth(Job* job,
                                   const SSLConfig& used_ssl_config,
                                   SSLCertRequestInfo* cert_info) = 0;

    // Invoked when |job| needs proxy authentication.
    virtual void OnNeedsProxyAuth(Job* job,
                                  const HttpResponseInfo& proxy_response,
                                  const SSLConfig& used_ssl_config,
                                  const ProxyInfo& used_proxy_info,
                                  HttpAuthController* auth_controller) = 0;

    // Returns true if the connection initialization to the proxy server
    // contained in |proxy_info| can be skipped.
    virtual bool OnInitConnection(const ProxyInfo& proxy_info) = 0;

    // Invoked when |job| has completed proxy resolution. The delegate may
    // create an alternative proxy server job to fetch the request.
    virtual void OnResolveProxyComplete(
        Job* job,
        const HttpRequestInfo& request_info,
        RequestPriority priority,
        const SSLConfig& server_ssl_config,
        const SSLConfig& proxy_ssl_config,
        HttpStreamRequest::StreamType stream_type) = 0;

    // Invoked to notify the Request and Factory of the readiness of new
    // SPDY session.
    virtual void OnNewSpdySessionReady(
        Job* job,
        const base::WeakPtr<SpdySession>& spdy_session,
        bool direct) = 0;

    // Invoked when the orphaned |job| finishes.
    virtual void OnOrphanedJobComplete(const Job* job) = 0;

    // Invoked when the |job| finishes pre-connecting sockets.
    virtual void OnPreconnectsComplete(Job* job) = 0;

    // Invoked to record connection attempts made by the socket layer to
    // Request if |job| is associated with Request.
    virtual void AddConnectionAttemptsToRequest(
        Job* job,
        const ConnectionAttempts& attempts) = 0;

    // Invoked when |job| finishes initiating a connection.
    virtual void OnConnectionInitialized(Job* job, int rv) = 0;

    // Return false if |job| can advance to the next state. Otherwise, |job|
    // will wait for Job::Resume() to be called before advancing.
    virtual bool ShouldWait(Job* job) = 0;

    // Called when |job| determines the appropriate |spdy_session_key| for the
    // Request. Note that this does not mean that SPDY is necessarily supported
    // for this SpdySessionKey, since we may need to wait for NPN to complete
    // before knowing if SPDY is available.
    virtual void SetSpdySessionKey(Job* job,
                                   const SpdySessionKey& spdy_session_key) = 0;

    // Remove session from the SpdySessionRequestMap.
    virtual void RemoveRequestFromSpdySessionRequestMapForJob(Job* job) = 0;

    virtual const NetLogWithSource* GetNetLog(Job* job) const = 0;

    virtual WebSocketHandshakeStreamBase::CreateHelper*
    websocket_handshake_stream_create_helper() = 0;

    virtual void MaybeSetWaitTimeForMainJob(const base::TimeDelta& delay) = 0;

    virtual bool for_websockets() = 0;
  };

  // Constructor for non-alternative Job.
  // Job is owned by |delegate|, hence |delegate| is valid for the
  // lifetime of the Job.
  Job(Delegate* delegate,
      JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      NetLog* net_log);

  // Constructor for the alternative Job. The Job is owned by |delegate|, hence
  // |delegate| is valid for the lifetime of the Job. If |alternative_service|
  // is initialized, then the Job will use the alternative service. On the
  // other hand, if |alternative_proxy_server| is a valid proxy server, then the
  // job will use that instead of using ProxyService for proxy resolution.
  // Further, if |alternative_proxy_server| is a valid but bad proxy, then
  // fallback proxies are not used. It is illegal to call this with an
  // initialized |alternative_service|, and a valid |alternative_proxy_server|.
  Job(Delegate* delegate,
      JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      AlternativeService alternative_service,
      const ProxyServer& alternative_proxy_server,
      NetLog* net_log);
  virtual ~Job();

  // Start initiates the process of creating a new HttpStream.
  // |delegate_| will be notified upon completion.
  void Start(HttpStreamRequest::StreamType stream_type);

  // Preconnect will attempt to request |num_streams| sockets from the
  // appropriate ClientSocketPool.
  int Preconnect(int num_streams);

  int RestartTunnelWithProxyAuth(const AuthCredentials& credentials);
  LoadState GetLoadState() const;

  // Tells |this| that |delegate_| has determined it still needs to continue
  // connecting.
  virtual void Resume();

  // Called to detach |this| Job. May resume the other Job, will disconnect
  // the socket for |this| Job, and notify |delegate| upon completion.
  void Orphan();

  void SetPriority(RequestPriority priority);

  RequestPriority priority() const { return priority_; }
  bool was_alpn_negotiated() const;
  NextProto negotiated_protocol() const;
  bool using_spdy() const;
  const NetLogWithSource& net_log() const { return net_log_; }
  HttpStreamRequest::StreamType stream_type() const { return stream_type_; }

  std::unique_ptr<HttpStream> ReleaseStream() { return std::move(stream_); }

  void SetStream(HttpStream* http_stream) { stream_.reset(http_stream); }

  std::unique_ptr<BidirectionalStreamImpl> ReleaseBidirectionalStream() {
    return std::move(bidirectional_stream_impl_);
  }

  bool is_waiting() const { return next_state_ == STATE_WAIT_COMPLETE; }
  const SSLConfig& server_ssl_config() const;
  const SSLConfig& proxy_ssl_config() const;
  const ProxyInfo& proxy_info() const;

  JobType job_type() const { return job_type_; }

  const AlternativeService alternative_service() const {
    return alternative_service_;
  }

  const ProxyServer alternative_proxy_server() const {
    return alternative_proxy_server_;
  }

  bool using_existing_quic_session() const {
    return using_existing_quic_session_;
  }

 private:
  friend class HttpStreamFactoryImplJobPeer;

  enum State {
    STATE_START,
    STATE_RESOLVE_PROXY,
    STATE_RESOLVE_PROXY_COMPLETE,

    // The main and alternative jobs are started in parallel.  The main job
    // waits after it finishes proxy resolution.  The alternative job never
    // waits.
    //
    // An HTTP/2 alternative job notifies the JobController in DoInitConnection
    // unless it can pool to an existing SpdySession.  JobController, in turn,
    // resumes the main job.
    //
    // A QUIC alternative job notifies the JobController in DoInitConnection
    // regardless of whether it pools to an existing QUIC session, but the main
    // job is only resumed after some delay.
    //
    // If the main job is resumed, then it races the alternative job.
    STATE_WAIT,
    STATE_WAIT_COMPLETE,

    STATE_INIT_CONNECTION,
    STATE_INIT_CONNECTION_COMPLETE,
    STATE_WAITING_USER_ACTION,
    STATE_RESTART_TUNNEL_AUTH,
    STATE_RESTART_TUNNEL_AUTH_COMPLETE,
    STATE_CREATE_STREAM,
    STATE_CREATE_STREAM_COMPLETE,
    STATE_DRAIN_BODY_FOR_AUTH_RESTART,
    STATE_DRAIN_BODY_FOR_AUTH_RESTART_COMPLETE,
    STATE_DONE,
    STATE_NONE
  };

  void OnStreamReadyCallback();
  void OnBidirectionalStreamImplReadyCallback();
  void OnWebSocketHandshakeStreamReadyCallback();
  // This callback function is called when a new SPDY session is created.
  void OnNewSpdySessionReadyCallback();
  void OnStreamFailedCallback(int result);
  void OnCertificateErrorCallback(int result, const SSLInfo& ssl_info);
  void OnNeedsProxyAuthCallback(const HttpResponseInfo& response_info,
                                HttpAuthController* auth_controller);
  void OnNeedsClientAuthCallback(SSLCertRequestInfo* cert_info);
  void OnHttpsProxyTunnelResponseCallback(const HttpResponseInfo& response_info,
                                          HttpStream* stream);
  void OnPreconnectsComplete();

  void OnIOComplete(int result);
  int RunLoop(int result);
  int DoLoop(int result);
  int StartInternal();
  int DoInitConnectionImpl();

  // Each of these methods corresponds to a State value.  Those with an input
  // argument receive the result from the previous state.  If a method returns
  // ERR_IO_PENDING, then the result from OnIOComplete will be passed to the
  // next state method as the result arg.
  int DoStart();
  int DoResolveProxy();
  int DoResolveProxyComplete(int result);
  int DoWait();
  int DoWaitComplete(int result);
  int DoInitConnection();
  int DoInitConnectionComplete(int result);
  int DoWaitingUserAction(int result);
  int DoCreateStream();
  int DoCreateStreamComplete(int result);
  int DoRestartTunnelAuth();
  int DoRestartTunnelAuthComplete(int result);

  // Creates a SpdyHttpStream or a BidirectionalStreamImpl from the given values
  // and sets to |stream_| or |bidirectional_stream_impl_| respectively. Does
  // nothing if |stream_factory_| is for WebSockets.
  int SetSpdyHttpStreamOrBidirectionalStreamImpl(
      base::WeakPtr<SpdySession> session,
      bool direct);

  // Returns to STATE_INIT_CONNECTION and resets some state.
  void ReturnToStateInitConnection(bool close_connection);

  // Set the motivation for this request onto the underlying socket.
  void SetSocketMotivation();

  bool IsHttpsProxyAndHttpUrl() const;

  // Is this a SPDY or QUIC alternative Job?
  bool IsSpdyAlternative() const;
  bool IsQuicAlternative() const;

  // Sets several fields of |ssl_config| based on the proxy info and other
  // factors.
  void InitSSLConfig(SSLConfig* ssl_config, bool is_proxy) const;

  // Retrieve SSLInfo from our SSL Socket.
  // This must only be called when we are using an SSLSocket.
  // After calling, the caller can use ssl_info_.
  void GetSSLInfo();

  SpdySessionKey GetSpdySessionKey() const;

  // Returns true if the current request can use an existing spdy session.
  bool CanUseExistingSpdySession() const;

  // Called when we encounter a network error that could be resolved by trying
  // a new proxy configuration.  If there is another proxy configuration to try
  // then this method sets next_state_ appropriately and returns either OK or
  // ERR_IO_PENDING depending on whether or not the new proxy configuration is
  // available synchronously or asynchronously.  Otherwise, the given error
  // code is simply returned.
  int ReconsiderProxyAfterError(int error);

  // Called to handle a certificate error.  Stores the certificate in the
  // allowed_bad_certs list, and checks if the error can be ignored.  Returns
  // OK if it can be ignored, or the error code otherwise.
  int HandleCertificateError(int error);

  // Called to handle a client certificate request.
  int HandleCertificateRequest(int error);

  // Should we force QUIC for this stream request.
  bool ShouldForceQuic() const;

  ClientSocketPoolManager::SocketGroupType GetSocketGroup() const;

  void MaybeCopyConnectionAttemptsFromSocketOrHandle();

  // Record histograms of latency until Connect() completes.
  static void LogHttpConnectedMetrics(const ClientSocketHandle& handle);

  // Invoked by the transport socket pool after host resolution is complete
  // to allow the connection to be aborted, if a matching SPDY session can
  // be found.  Will return ERR_SPDY_SESSION_ALREADY_EXISTS if such a
  // session is found, and OK otherwise.
  static int OnHostResolution(SpdySessionPool* spdy_session_pool,
                              const SpdySessionKey& spdy_session_key,
                              const GURL& origin_url,
                              const AddressList& addresses,
                              const NetLogWithSource& net_log);

  const HttpRequestInfo request_info_;
  RequestPriority priority_;
  ProxyInfo proxy_info_;
  SSLConfig server_ssl_config_;
  SSLConfig proxy_ssl_config_;
  const NetLogWithSource net_log_;

  CompletionCallback io_callback_;
  std::unique_ptr<ClientSocketHandle> connection_;
  HttpNetworkSession* const session_;
  State next_state_;
  ProxyService::PacRequest* pac_request_;
  SSLInfo ssl_info_;

  // The server we are trying to reach, could be that of the origin or of the
  // alternative service (after applying host mapping rules).
  const HostPortPair destination_;

  // The origin url we're trying to reach. This url may be different from the
  // original request when host mapping rules are set-up.
  const GURL origin_url_;

  // AlternativeService for this Job if this is an alternative Job.
  const AlternativeService alternative_service_;

  // Alternative proxy server that should be used by |this| to fetch the
  // request.
  const ProxyServer alternative_proxy_server_;

  // Unowned. |this| job is owned by |delegate_|.
  Delegate* delegate_;

  const JobType job_type_;

  // True if handling a HTTPS request, or using SPDY with SSL
  bool using_ssl_;

  // True if this network transaction is using SPDY instead of HTTP.
  bool using_spdy_;

  // True if this network transaction is using QUIC instead of HTTP.
  bool using_quic_;
  QuicStreamRequest quic_request_;

  // True if this job used an existing QUIC session.
  bool using_existing_quic_session_;

  // Force quic for a specific port.
  int force_quic_port_;

  scoped_refptr<HttpAuthController>
      auth_controllers_[HttpAuth::AUTH_NUM_TARGETS];

  // True when the tunnel is in the process of being established - we can't
  // read from the socket until the tunnel is done.
  bool establishing_tunnel_;

  std::unique_ptr<HttpStream> stream_;
  std::unique_ptr<WebSocketHandshakeStreamBase> websocket_stream_;
  std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_impl_;

  // True if we negotiated ALPN.
  bool was_alpn_negotiated_;

  // Protocol negotiated with the server.
  NextProto negotiated_protocol_;

  // 0 if we're not preconnecting. Otherwise, the number of streams to
  // preconnect.
  int num_streams_;

  // Initialized when we create a new SpdySession.
  base::WeakPtr<SpdySession> new_spdy_session_;

  // Initialized when we have an existing SpdySession.
  base::WeakPtr<SpdySession> existing_spdy_session_;

  // Only used if |new_spdy_session_| is non-NULL.
  bool spdy_session_direct_;

  // Type of stream that is requested.
  HttpStreamRequest::StreamType stream_type_;

  base::WeakPtrFactory<Job> ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(Job);
};

// Factory for creating Jobs.
class HttpStreamFactoryImpl::JobFactory {
 public:
  virtual ~JobFactory() {}

  // Creates an alternative service Job.
  virtual HttpStreamFactoryImpl::Job* CreateJob(
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
      NetLog* net_log) = 0;

  // Creates an alternative proxy server Job.
  virtual HttpStreamFactoryImpl::Job* CreateJob(
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
      NetLog* net_log) = 0;

  // Creates a non-alternative Job.
  virtual HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      NetLog* net_log) = 0;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_IMPL_JOB_H_
