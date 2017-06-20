// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_job_controller.h"

#include <string>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/values.h"
#include "net/base/host_mapping_rules.h"
#include "net/base/proxy_delegate.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/proxy_server.h"
#include "net/spdy/chromium/spdy_session.h"
#include "url/url_constants.h"

namespace net {

namespace {

// Returns parameters associated with the proxy resolution.
std::unique_ptr<base::Value> NetLogHttpStreamJobProxyServerResolved(
    const ProxyServer& proxy_server,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  dict->SetString("proxy_server", proxy_server.is_valid()
                                      ? proxy_server.ToPacString()
                                      : std::string());
  return std::move(dict);
}

}  // namespace

// The maximum time to wait for the alternate job to complete before resuming
// the main job.
const int kMaxDelayTimeForMainJobSecs = 3;

std::unique_ptr<base::Value> NetLogJobControllerCallback(
    const GURL* url,
    bool is_preconnect,
    NetLogCaptureMode /* capture_mode */) {
  auto dict = base::MakeUnique<base::DictionaryValue>();
  dict->SetString("url", url->possibly_invalid_spec());
  dict->SetBoolean("is_preconnect", is_preconnect);
  return std::move(dict);
}

HttpStreamFactoryImpl::JobController::JobController(
    HttpStreamFactoryImpl* factory,
    HttpStreamRequest::Delegate* delegate,
    HttpNetworkSession* session,
    JobFactory* job_factory,
    const HttpRequestInfo& request_info,
    bool is_preconnect,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config)
    : factory_(factory),
      session_(session),
      job_factory_(job_factory),
      request_(nullptr),
      delegate_(delegate),
      is_preconnect_(is_preconnect),
      enable_ip_based_pooling_(enable_ip_based_pooling),
      enable_alternative_services_(enable_alternative_services),
      alternative_job_net_error_(OK),
      job_bound_(false),
      main_job_is_blocked_(false),
      main_job_is_resumed_(false),
      bound_job_(nullptr),
      can_start_alternative_proxy_job_(true),
      next_state_(STATE_RESOLVE_PROXY),
      pac_request_(nullptr),
      io_callback_(
          base::Bind(&JobController::OnIOComplete, base::Unretained(this))),
      request_info_(request_info),
      server_ssl_config_(server_ssl_config),
      proxy_ssl_config_(proxy_ssl_config),
      num_streams_(0),
      priority_(IDLE),
      net_log_(
          NetLogWithSource::Make(session->net_log(),
                                 NetLogSourceType::HTTP_STREAM_JOB_CONTROLLER)),
      ptr_factory_(this) {
  DCHECK(factory);
  net_log_.BeginEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER,
                      base::Bind(&NetLogJobControllerCallback,
                                 &request_info.url, is_preconnect));
}

HttpStreamFactoryImpl::JobController::~JobController() {
  main_job_.reset();
  alternative_job_.reset();
  bound_job_ = nullptr;
  if (pac_request_) {
    DCHECK_EQ(STATE_RESOLVE_PROXY_COMPLETE, next_state_);
    session_->proxy_service()->CancelPacRequest(pac_request_);
  }
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER);
}

bool HttpStreamFactoryImpl::JobController::for_websockets() {
  return factory_->for_websockets_;
}

std::unique_ptr<HttpStreamFactoryImpl::Request>
HttpStreamFactoryImpl::JobController::Start(
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    const NetLogWithSource& source_net_log,
    HttpStreamRequest::StreamType stream_type,
    RequestPriority priority) {
  DCHECK(factory_);
  DCHECK(!request_);

  stream_type_ = stream_type;
  priority_ = priority;

  auto request = base::MakeUnique<Request>(
      request_info_.url, this, delegate,
      websocket_handshake_stream_create_helper, source_net_log, stream_type);
  // Keep a raw pointer but release ownership of Request instance.
  request_ = request.get();

  // Associates |net_log_| with |source_net_log|.
  source_net_log.AddEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND,
                          net_log_.source().ToEventParametersCallback());
  net_log_.AddEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND,
                    source_net_log.source().ToEventParametersCallback());

  RunLoop(OK);
  return request;
}

void HttpStreamFactoryImpl::JobController::Preconnect(int num_streams) {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);
  DCHECK(is_preconnect_);

  stream_type_ = HttpStreamRequest::HTTP_STREAM;
  num_streams_ = num_streams;

  RunLoop(OK);
}

LoadState HttpStreamFactoryImpl::JobController::GetLoadState() const {
  DCHECK(request_);
  if (next_state_ == STATE_RESOLVE_PROXY_COMPLETE)
    return session_->proxy_service()->GetLoadState(pac_request_);
  if (bound_job_)
    return bound_job_->GetLoadState();
  if (main_job_)
    return main_job_->GetLoadState();
  if (alternative_job_)
    return alternative_job_->GetLoadState();
  // When proxy resolution fails, there is no job created and
  // NotifyRequestFailed() is executed one message loop iteration later.
  return LOAD_STATE_IDLE;
}

void HttpStreamFactoryImpl::JobController::OnRequestComplete() {
  DCHECK(request_);

  RemoveRequestFromSpdySessionRequestMap();
  CancelJobs();
  request_ = nullptr;
  if (bound_job_) {
    if (bound_job_->job_type() == MAIN) {
      main_job_.reset();
      // |alternative_job_| can be non-null if |main_job_| is resumed after
      // |main_job_wait_time_| has elapsed. Allow |alternative_job_| to run to
      // completion, rather than resetting it. OnOrphanedJobComplete() will
      // clean up |this| when the job completes.
    } else {
      DCHECK(bound_job_->job_type() == ALTERNATIVE);
      alternative_job_.reset();
    }
    bound_job_ = nullptr;
  }
  MaybeNotifyFactoryOfCompletion();
}

int HttpStreamFactoryImpl::JobController::RestartTunnelWithProxyAuth() {
  DCHECK(bound_job_);
  return bound_job_->RestartTunnelWithProxyAuth();
}

void HttpStreamFactoryImpl::JobController::SetPriority(
    RequestPriority priority) {
  if (main_job_) {
    main_job_->SetPriority(priority);
  }
  if (alternative_job_) {
    alternative_job_->SetPriority(priority);
  }
}

void HttpStreamFactoryImpl::JobController::OnStreamReady(
    Job* job,
    const SSLConfig& used_ssl_config) {
  DCHECK(job);

  factory_->OnStreamReady(job->proxy_info(), request_info_.privacy_mode);

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }
  std::unique_ptr<HttpStream> stream = job->ReleaseStream();
  DCHECK(stream);

  MarkRequestComplete(job->was_alpn_negotiated(), job->negotiated_protocol(),
                      job->using_spdy());

  if (!request_)
    return;
  DCHECK(!factory_->for_websockets_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, request_->stream_type());
  OnJobSucceeded(job);
  request_->OnStreamReady(used_ssl_config, job->proxy_info(),
                          std::move(stream));
}

void HttpStreamFactoryImpl::JobController::OnBidirectionalStreamImplReady(
    Job* job,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info) {
  DCHECK(job);

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  MarkRequestComplete(job->was_alpn_negotiated(), job->negotiated_protocol(),
                      job->using_spdy());

  if (!request_)
    return;
  std::unique_ptr<BidirectionalStreamImpl> stream =
      job->ReleaseBidirectionalStream();
  DCHECK(stream);
  DCHECK(!factory_->for_websockets_);
  DCHECK_EQ(HttpStreamRequest::BIDIRECTIONAL_STREAM, request_->stream_type());

  OnJobSucceeded(job);
  request_->OnBidirectionalStreamImplReady(used_ssl_config, used_proxy_info,
                                           std::move(stream));
}

void HttpStreamFactoryImpl::JobController::OnWebSocketHandshakeStreamReady(
    Job* job,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<WebSocketHandshakeStreamBase> stream) {
  DCHECK(job);
  MarkRequestComplete(job->was_alpn_negotiated(), job->negotiated_protocol(),
                      job->using_spdy());

  if (!request_)
    return;
  DCHECK(factory_->for_websockets_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, request_->stream_type());
  DCHECK(stream);

  OnJobSucceeded(job);
  request_->OnWebSocketHandshakeStreamReady(used_ssl_config, used_proxy_info,
                                            std::move(stream));
}

void HttpStreamFactoryImpl::JobController::OnStreamFailed(
    Job* job,
    int status,
    const SSLConfig& used_ssl_config) {
  if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    if (alternative_job_->alternative_proxy_server().is_valid()) {
      OnAlternativeProxyJobFailed(status);
    } else {
      OnAlternativeServiceJobFailed(status);
    }
  }

  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_)
    return;
  DCHECK_NE(OK, status);
  DCHECK(job);

  if (!bound_job_) {
    if (main_job_ && alternative_job_) {
      // Hey, we've got other jobs! Maybe one of them will succeed, let's just
      // ignore this failure.
      if (job->job_type() == MAIN) {
        main_job_.reset();
      } else {
        DCHECK(job->job_type() == ALTERNATIVE);
        alternative_job_.reset();
      }
      return;
    } else {
      BindJob(job);
    }
  }

  status = ReconsiderProxyAfterError(job, status);
  if (next_state_ == STATE_RESOLVE_PROXY_COMPLETE) {
    if (status == ERR_IO_PENDING)
      return;
    DCHECK_EQ(OK, status);
    RunLoop(status);
    return;
  }
  request_->OnStreamFailed(status, used_ssl_config);
}

void HttpStreamFactoryImpl::JobController::OnCertificateError(
    Job* job,
    int status,
    const SSLConfig& used_ssl_config,
    const SSLInfo& ssl_info) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_)
    return;
  DCHECK_NE(OK, status);
  if (!bound_job_)
    BindJob(job);

  request_->OnCertificateError(status, used_ssl_config, ssl_info);
}

void HttpStreamFactoryImpl::JobController::OnHttpsProxyTunnelResponse(
    Job* job,
    const HttpResponseInfo& response_info,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    std::unique_ptr<HttpStream> stream) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!bound_job_)
    BindJob(job);
  if (!request_)
    return;
  request_->OnHttpsProxyTunnelResponse(response_info, used_ssl_config,
                                       used_proxy_info, std::move(stream));
}

void HttpStreamFactoryImpl::JobController::OnNeedsClientAuth(
    Job* job,
    const SSLConfig& used_ssl_config,
    SSLCertRequestInfo* cert_info) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }
  if (!request_)
    return;
  if (!bound_job_)
    BindJob(job);

  request_->OnNeedsClientAuth(used_ssl_config, cert_info);
}

void HttpStreamFactoryImpl::JobController::OnNeedsProxyAuth(
    Job* job,
    const HttpResponseInfo& proxy_response,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  MaybeResumeMainJob(job, base::TimeDelta());

  if (IsJobOrphaned(job)) {
    // We have bound a job to the associated Request, |job| has been orphaned.
    OnOrphanedJobComplete(job);
    return;
  }

  if (!request_)
    return;
  if (!bound_job_)
    BindJob(job);
  request_->OnNeedsProxyAuth(proxy_response, used_ssl_config, used_proxy_info,
                             auth_controller);
}

bool HttpStreamFactoryImpl::JobController::OnInitConnection(
    const ProxyInfo& proxy_info) {
  return factory_->OnInitConnection(*this, proxy_info,
                                    request_info_.privacy_mode);
}

void HttpStreamFactoryImpl::JobController::OnNewSpdySessionReady(
    Job* job,
    const base::WeakPtr<SpdySession>& spdy_session,
    bool direct) {
  DCHECK(job);
  DCHECK(job->using_spdy());
  DCHECK(!is_preconnect_);

  bool is_job_orphaned = IsJobOrphaned(job);

  // Cache these values in case the job gets deleted.
  const SSLConfig used_ssl_config = job->server_ssl_config();
  const ProxyInfo used_proxy_info = job->proxy_info();
  const bool was_alpn_negotiated = job->was_alpn_negotiated();
  const NextProto negotiated_protocol = job->negotiated_protocol();
  const bool using_spdy = job->using_spdy();
  const NetLogSource source_dependency = job->net_log().source();

  // Cache this so we can still use it if the JobController is deleted.
  SpdySessionPool* spdy_session_pool = session_->spdy_session_pool();

  // Notify |request_|.
  if (!is_preconnect_ && !is_job_orphaned) {
    if (job->job_type() == MAIN && alternative_job_net_error_ != OK)
      ReportBrokenAlternativeService();

    DCHECK(request_);

    // The first case is the usual case.
    if (!job_bound_) {
      BindJob(job);
    }

    MarkRequestComplete(was_alpn_negotiated, negotiated_protocol, using_spdy);

    if (for_websockets()) {
      // TODO(ricea): Re-instate this code when WebSockets over SPDY is
      // implemented.
      NOTREACHED();
    } else if (job->stream_type() == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
      std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_impl =
          job->ReleaseBidirectionalStream();
      DCHECK(bidirectional_stream_impl);
      delegate_->OnBidirectionalStreamImplReady(
          used_ssl_config, used_proxy_info,
          std::move(bidirectional_stream_impl));
    } else {
      std::unique_ptr<HttpStream> stream = job->ReleaseStream();
      DCHECK(stream);
      delegate_->OnStreamReady(used_ssl_config, used_proxy_info,
                               std::move(stream));
    }
  }

  // Notify other requests that have the same SpdySessionKey. |request_| and
  // |bounded_job_| might be deleted already.
  if (spdy_session && spdy_session->IsAvailable()) {
    spdy_session_pool->OnNewSpdySessionReady(
        spdy_session, direct, used_ssl_config, used_proxy_info,
        was_alpn_negotiated, negotiated_protocol, using_spdy,
        source_dependency);
  }
  if (is_job_orphaned) {
    OnOrphanedJobComplete(job);
  }
}

void HttpStreamFactoryImpl::JobController::OnPreconnectsComplete(Job* job) {
  DCHECK_EQ(main_job_.get(), job);
  main_job_.reset();
  factory_->OnPreconnectsCompleteInternal();
  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactoryImpl::JobController::OnOrphanedJobComplete(
    const Job* job) {
  if (job->job_type() == MAIN) {
    DCHECK_EQ(main_job_.get(), job);
    main_job_.reset();
  } else {
    DCHECK_EQ(alternative_job_.get(), job);
    alternative_job_.reset();
  }

  MaybeNotifyFactoryOfCompletion();
}

void HttpStreamFactoryImpl::JobController::AddConnectionAttemptsToRequest(
    Job* job,
    const ConnectionAttempts& attempts) {
  if (is_preconnect_ || IsJobOrphaned(job))
    return;

  request_->AddConnectionAttempts(attempts);
}

void HttpStreamFactoryImpl::JobController::ResumeMainJobLater(
    const base::TimeDelta& delay) {
  net_log_.AddEvent(NetLogEventType::HTTP_STREAM_JOB_DELAYED,
                    NetLog::Int64Callback("delay", delay.InMilliseconds()));
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&HttpStreamFactoryImpl::JobController::ResumeMainJob,
                 ptr_factory_.GetWeakPtr()),
      delay);
}

void HttpStreamFactoryImpl::JobController::ResumeMainJob() {
  if (main_job_is_resumed_)
    return;

  main_job_is_resumed_ = true;
  main_job_->net_log().AddEvent(
      NetLogEventType::HTTP_STREAM_JOB_RESUMED,
      NetLog::Int64Callback("delay", main_job_wait_time_.InMilliseconds()));

  main_job_->Resume();
  main_job_wait_time_ = base::TimeDelta();
}

void HttpStreamFactoryImpl::JobController::MaybeResumeMainJob(
    Job* job,
    const base::TimeDelta& delay) {
  DCHECK(delay == base::TimeDelta() || delay == main_job_wait_time_);
  DCHECK(job == main_job_.get() || job == alternative_job_.get());

  if (job != alternative_job_.get() || !main_job_)
    return;

  main_job_is_blocked_ = false;

  if (!main_job_->is_waiting()) {
    // There are two cases where the main job is not in WAIT state:
    //   1) The main job hasn't got to waiting state, do not yet post a task to
    //      resume since that will happen in ShouldWait().
    //   2) The main job has passed waiting state, so the main job does not need
    //      to be resumed.
    return;
  }

  main_job_wait_time_ = delay;

  ResumeMainJobLater(main_job_wait_time_);
}

void HttpStreamFactoryImpl::JobController::OnConnectionInitialized(Job* job,
                                                                   int rv) {
  if (rv != OK) {
    // Resume the main job as there's an error raised in connection
    // initiation.
    return MaybeResumeMainJob(job, main_job_wait_time_);
  }
}

bool HttpStreamFactoryImpl::JobController::ShouldWait(Job* job) {
  // The alternative job never waits.
  if (job == alternative_job_.get())
    return false;

  if (main_job_is_blocked_)
    return true;

  if (main_job_wait_time_.is_zero())
    return false;

  ResumeMainJobLater(main_job_wait_time_);
  return true;
}

void HttpStreamFactoryImpl::JobController::SetSpdySessionKey(
    Job* job,
    const SpdySessionKey& spdy_session_key) {
  DCHECK(!job->using_quic());

  if (is_preconnect_ || IsJobOrphaned(job))
    return;

  session_->spdy_session_pool()->AddRequestToSpdySessionRequestMap(
      spdy_session_key, request_);
}

void HttpStreamFactoryImpl::JobController::
    RemoveRequestFromSpdySessionRequestMapForJob(Job* job) {
  DCHECK(!job->using_quic());

  if (is_preconnect_ || IsJobOrphaned(job))
    return;

  RemoveRequestFromSpdySessionRequestMap();
}

void HttpStreamFactoryImpl::JobController::
    RemoveRequestFromSpdySessionRequestMap() {
  // TODO(xunjieli): Use a DCHECK once https://crbug.com/718576 is fixed.
  CHECK(request_);
  session_->spdy_session_pool()->RemoveRequestFromSpdySessionRequestMap(
      request_);
}

const NetLogWithSource* HttpStreamFactoryImpl::JobController::GetNetLog()
    const {
  return &net_log_;
}

void HttpStreamFactoryImpl::JobController::MaybeSetWaitTimeForMainJob(
    const base::TimeDelta& delay) {
  if (main_job_is_blocked_) {
    main_job_wait_time_ = std::min(
        delay, base::TimeDelta::FromSeconds(kMaxDelayTimeForMainJobSecs));
  }
}

bool HttpStreamFactoryImpl::JobController::HasPendingMainJob() const {
  return main_job_.get() != nullptr;
}

bool HttpStreamFactoryImpl::JobController::HasPendingAltJob() const {
  return alternative_job_.get() != nullptr;
}

void HttpStreamFactoryImpl::JobController::LogHistograms() const {
  if (main_job_)
    main_job_->LogHistograms();
  if (alternative_job_)
    alternative_job_->LogHistograms();
}

size_t HttpStreamFactoryImpl::JobController::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(main_job_) +
         base::trace_event::EstimateMemoryUsage(alternative_job_);
}

WebSocketHandshakeStreamBase::CreateHelper* HttpStreamFactoryImpl::
    JobController::websocket_handshake_stream_create_helper() {
  DCHECK(request_);
  return request_->websocket_handshake_stream_create_helper();
}

void HttpStreamFactoryImpl::JobController::OnIOComplete(int result) {
  RunLoop(result);
}

void HttpStreamFactoryImpl::JobController::RunLoop(int result) {
  int rv = DoLoop(result);
  if (rv == ERR_IO_PENDING)
    return;
  if (rv != OK) {
    // DoLoop can only fail during proxy resolution step which happens before
    // any jobs are created. Notify |request_| of the failure one message loop
    // iteration later to avoid re-entrancy.
    DCHECK(!main_job_);
    DCHECK(!alternative_job_);
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&HttpStreamFactoryImpl::JobController::NotifyRequestFailed,
                   ptr_factory_.GetWeakPtr(), rv));
  }
}

int HttpStreamFactoryImpl::JobController::DoLoop(int rv) {
  DCHECK_NE(next_state_, STATE_NONE);
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_PROXY:
        DCHECK_EQ(OK, rv);
        rv = DoResolveProxy();
        break;
      case STATE_RESOLVE_PROXY_COMPLETE:
        rv = DoResolveProxyComplete(rv);
        break;
      case STATE_CREATE_JOBS:
        DCHECK_EQ(OK, rv);
        rv = DoCreateJobs();
        break;
      default:
        NOTREACHED() << "bad state";
        break;
    }
  } while (next_state_ != STATE_NONE && rv != ERR_IO_PENDING);
  return rv;
}

int HttpStreamFactoryImpl::JobController::DoResolveProxy() {
  DCHECK(!pac_request_);
  DCHECK(session_);

  next_state_ = STATE_RESOLVE_PROXY_COMPLETE;

  if (request_info_.load_flags & LOAD_BYPASS_PROXY) {
    proxy_info_.UseDirect();
    return OK;
  }

  HostPortPair destination(HostPortPair::FromURL(request_info_.url));
  GURL origin_url = ApplyHostMappingRules(request_info_.url, &destination);

  return session_->proxy_service()->ResolveProxy(
      origin_url, request_info_.method, &proxy_info_, io_callback_,
      &pac_request_, session_->context().proxy_delegate, net_log_);
}

int HttpStreamFactoryImpl::JobController::DoResolveProxyComplete(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);

  pac_request_ = nullptr;
  net_log_.AddEvent(
      NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_PROXY_SERVER_RESOLVED,
      base::Bind(
          &NetLogHttpStreamJobProxyServerResolved,
          proxy_info_.is_empty() ? ProxyServer() : proxy_info_.proxy_server()));

  if (rv != OK)
    return rv;
  // Remove unsupported proxies from the list.
  int supported_proxies = ProxyServer::SCHEME_DIRECT |
                          ProxyServer::SCHEME_HTTP | ProxyServer::SCHEME_HTTPS |
                          ProxyServer::SCHEME_SOCKS4 |
                          ProxyServer::SCHEME_SOCKS5;
  if (session_->IsQuicEnabled())
    supported_proxies |= ProxyServer::SCHEME_QUIC;
  proxy_info_.RemoveProxiesWithoutScheme(supported_proxies);

  if (proxy_info_.is_empty()) {
    // No proxies/direct to choose from.
    return ERR_NO_SUPPORTED_PROXIES;
  }

  next_state_ = STATE_CREATE_JOBS;
  return rv;
}

int HttpStreamFactoryImpl::JobController::DoCreateJobs() {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);

  HostPortPair destination(HostPortPair::FromURL(request_info_.url));
  GURL origin_url = ApplyHostMappingRules(request_info_.url, &destination);

  // Create an alternative job if alternative service is set up for this domain.
  alternative_service_ =
      GetAlternativeServiceInfoFor(request_info_, delegate_, stream_type_)
          .alternative_service();

  if (is_preconnect_) {
    // Due to how the socket pools handle priorities and idle sockets, only IDLE
    // priority currently makes sense for preconnects. The priority for
    // preconnects is currently ignored (see RequestSocketsForPool()), but could
    // be used at some point for proxy resolution or something.
    if (alternative_service_.protocol != kProtoUnknown) {
      HostPortPair alternative_destination(
          alternative_service_.host_port_pair());
      ignore_result(
          ApplyHostMappingRules(request_info_.url, &alternative_destination));
      main_job_ = job_factory_->CreateAltSvcJob(
          this, PRECONNECT, session_, request_info_, IDLE, proxy_info_,
          server_ssl_config_, proxy_ssl_config_, alternative_destination,
          origin_url, alternative_service_.protocol, enable_ip_based_pooling_,
          session_->net_log());
    } else {
      main_job_ = job_factory_->CreateMainJob(
          this, PRECONNECT, session_, request_info_, IDLE, proxy_info_,
          server_ssl_config_, proxy_ssl_config_, destination, origin_url,
          enable_ip_based_pooling_, session_->net_log());
    }
    main_job_->Preconnect(num_streams_);
    return OK;
  }
  main_job_ = job_factory_->CreateMainJob(
      this, MAIN, session_, request_info_, priority_, proxy_info_,
      server_ssl_config_, proxy_ssl_config_, destination, origin_url,
      enable_ip_based_pooling_, net_log_.net_log());
  // Alternative Service can only be set for HTTPS requests while Alternative
  // Proxy is set for HTTP requests.
  if (alternative_service_.protocol != kProtoUnknown) {
    // Never share connection with other jobs for FTP requests.
    DVLOG(1) << "Selected alternative service (host: "
             << alternative_service_.host_port_pair().host()
             << " port: " << alternative_service_.host_port_pair().port()
             << ")";

    DCHECK(!request_info_.url.SchemeIs(url::kFtpScheme));
    HostPortPair alternative_destination(alternative_service_.host_port_pair());
    ignore_result(
        ApplyHostMappingRules(request_info_.url, &alternative_destination));

    alternative_job_ = job_factory_->CreateAltSvcJob(
        this, ALTERNATIVE, session_, request_info_, priority_, proxy_info_,
        server_ssl_config_, proxy_ssl_config_, alternative_destination,
        origin_url, alternative_service_.protocol, enable_ip_based_pooling_,
        net_log_.net_log());

    main_job_is_blocked_ = true;
    alternative_job_->Start(request_->stream_type());
  } else {
    ProxyServer alternative_proxy_server;
    if (ShouldCreateAlternativeProxyServerJob(proxy_info_, request_info_.url,
                                              &alternative_proxy_server)) {
      DCHECK(!main_job_is_blocked_);
      ProxyInfo alternative_proxy_info;
      alternative_proxy_info.UseProxyServer(alternative_proxy_server);

      alternative_job_ = job_factory_->CreateAltProxyJob(
          this, ALTERNATIVE, session_, request_info_, priority_,
          alternative_proxy_info, server_ssl_config_, proxy_ssl_config_,
          destination, origin_url, alternative_proxy_server,
          enable_ip_based_pooling_, net_log_.net_log());

      can_start_alternative_proxy_job_ = false;
      main_job_is_blocked_ = true;
      alternative_job_->Start(request_->stream_type());
    }
  }
  // Even if |alternative_job| has already finished, it will not have notified
  // the request yet, since we defer that to the next iteration of the
  // MessageLoop, so starting |main_job_| is always safe.
  main_job_->Start(request_->stream_type());
  return OK;
}

void HttpStreamFactoryImpl::JobController::BindJob(Job* job) {
  DCHECK(request_);
  DCHECK(job);
  DCHECK(job == alternative_job_.get() || job == main_job_.get());
  DCHECK(!job_bound_);
  DCHECK(!bound_job_);

  job_bound_ = true;
  bound_job_ = job;

  request_->net_log().AddEvent(
      NetLogEventType::HTTP_STREAM_REQUEST_BOUND_TO_JOB,
      job->net_log().source().ToEventParametersCallback());
  job->net_log().AddEvent(
      NetLogEventType::HTTP_STREAM_JOB_BOUND_TO_REQUEST,
      request_->net_log().source().ToEventParametersCallback());

  OrphanUnboundJob();
}

void HttpStreamFactoryImpl::JobController::CancelJobs() {
  DCHECK(request_);
  if (job_bound_)
    return;
  if (alternative_job_)
    alternative_job_.reset();
  if (main_job_)
    main_job_.reset();
}

void HttpStreamFactoryImpl::JobController::OrphanUnboundJob() {
  DCHECK(request_);
  DCHECK(bound_job_);
  RemoveRequestFromSpdySessionRequestMap();

  if (bound_job_->job_type() == MAIN && alternative_job_) {
    DCHECK(!for_websockets());
    alternative_job_->Orphan();
  } else if (bound_job_->job_type() == ALTERNATIVE && main_job_) {
    // Orphan main job.
    // If ResumeMainJob() is not executed, reset |main_job_|. Otherwise,
    // OnOrphanedJobComplete() will clean up |this| when the job completes.
    // Use |main_job_is_blocked_| and |!main_job_wait_time_.is_zero()| instead
    // of |main_job_|->is_waiting() because |main_job_| can be in proxy
    // resolution step.
    if (main_job_ && (main_job_is_blocked_ || !main_job_wait_time_.is_zero())) {
      DCHECK(alternative_job_);
      main_job_.reset();
    } else {
      DCHECK(!for_websockets());
      main_job_->Orphan();
    }
  }
}

void HttpStreamFactoryImpl::JobController::OnJobSucceeded(Job* job) {
  // |job| should only be nullptr if we're being serviced by a late bound
  // SpdySession (one that was not created by a job in our |jobs_| set).
  if (!job) {
    // TODO(xunjieli): This seems to be dead code. Remove it. crbug.com/475060.
    CHECK(false);
    DCHECK(!bound_job_);
    // NOTE(willchan): We do *NOT* call OrphanUnboundJob() here. The reason is
    // because we *WANT* to cancel the unnecessary Jobs from other requests if
    // another Job completes first.
    // TODO(mbelshe): Revisit this when we implement ip connection pooling of
    // SpdySessions. Do we want to orphan the jobs for a different hostname so
    // they complete? Or do we want to prevent connecting a new SpdySession if
    // we've already got one available for a different hostname where the ip
    // address matches up?
    CancelJobs();
    return;
  }

  if (job->job_type() == MAIN && alternative_job_net_error_ != OK)
    ReportBrokenAlternativeService();

  if (!bound_job_) {
    if (main_job_ && alternative_job_)
      ReportAlternateProtocolUsage(job);
    BindJob(job);
    return;
  }
  DCHECK(bound_job_);
}

void HttpStreamFactoryImpl::JobController::MarkRequestComplete(
    bool was_alpn_negotiated,
    NextProto negotiated_protocol,
    bool using_spdy) {
  if (request_)
    request_->Complete(was_alpn_negotiated, negotiated_protocol, using_spdy);
}

void HttpStreamFactoryImpl::JobController::OnAlternativeServiceJobFailed(
    int net_error) {
  DCHECK_EQ(alternative_job_->job_type(), ALTERNATIVE);
  DCHECK_NE(OK, net_error);
  DCHECK_NE(kProtoUnknown, alternative_service_.protocol);

  alternative_job_net_error_ = net_error;

  if (IsJobOrphaned(alternative_job_.get())) {
    // If |request_| is gone then it must have been successfully served by
    // |main_job_|.
    // If |request_| is bound to a different job, then it is being
    // successfully serverd by the main job.
    ReportBrokenAlternativeService();
  }
}

void HttpStreamFactoryImpl::JobController::OnAlternativeProxyJobFailed(
    int net_error) {
  DCHECK_EQ(alternative_job_->job_type(), ALTERNATIVE);
  DCHECK_NE(OK, net_error);
  DCHECK(alternative_job_->alternative_proxy_server().is_valid());

  // Need to mark alt proxy as broken regardless whether the job is bound.
  ProxyDelegate* proxy_delegate = session_->context().proxy_delegate;
  if (proxy_delegate) {
    proxy_delegate->OnAlternativeProxyBroken(
        alternative_job_->alternative_proxy_server());
  }
}

void HttpStreamFactoryImpl::JobController::ReportBrokenAlternativeService() {
  DCHECK(alternative_service_.protocol != kProtoUnknown);
  DCHECK_NE(OK, alternative_job_net_error_);

  int error_to_report = alternative_job_net_error_;
  alternative_job_net_error_ = OK;
  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.AlternateServiceFailed", -error_to_report);

  if (error_to_report == ERR_NETWORK_CHANGED ||
      error_to_report == ERR_INTERNET_DISCONNECTED) {
    // No need to mark alternative service or proxy as broken.
    return;
  }

  HistogramBrokenAlternateProtocolLocation(
      BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_STREAM_FACTORY_IMPL_JOB_ALT);
  session_->http_server_properties()->MarkAlternativeServiceBroken(
      alternative_service_);
}

void HttpStreamFactoryImpl::JobController::MaybeNotifyFactoryOfCompletion() {
  if (!request_ && !main_job_ && !alternative_job_) {
    DCHECK(!bound_job_);
    factory_->OnJobControllerComplete(this);
  }
}

void HttpStreamFactoryImpl::JobController::NotifyRequestFailed(int rv) {
  if (!request_)
    return;
  request_->OnStreamFailed(rv, server_ssl_config_);
}

GURL HttpStreamFactoryImpl::JobController::ApplyHostMappingRules(
    const GURL& url,
    HostPortPair* endpoint) {
  if (session_->params().host_mapping_rules.RewriteHost(endpoint)) {
    url::Replacements<char> replacements;
    const std::string port_str = base::UintToString(endpoint->port());
    replacements.SetPort(port_str.c_str(), url::Component(0, port_str.size()));
    replacements.SetHost(endpoint->host().c_str(),
                         url::Component(0, endpoint->host().size()));
    return url.ReplaceComponents(replacements);
  }
  return url;
}

AlternativeServiceInfo
HttpStreamFactoryImpl::JobController::GetAlternativeServiceInfoFor(
    const HttpRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  if (!enable_alternative_services_)
    return AlternativeServiceInfo();

  AlternativeServiceInfo alternative_service_info =
      GetAlternativeServiceInfoInternal(request_info, delegate, stream_type);
  AlternativeServiceType type;
  if (alternative_service_info.alternative_service().protocol ==
      kProtoUnknown) {
    type = NO_ALTERNATIVE_SERVICE;
  } else if (alternative_service_info.alternative_service().protocol ==
             kProtoQUIC) {
    if (request_info.url.host_piece() ==
        alternative_service_info.alternative_service().host) {
      type = QUIC_SAME_DESTINATION;
    } else {
      type = QUIC_DIFFERENT_DESTINATION;
    }
  } else {
    if (request_info.url.host_piece() ==
        alternative_service_info.alternative_service().host) {
      type = NOT_QUIC_SAME_DESTINATION;
    } else {
      type = NOT_QUIC_DIFFERENT_DESTINATION;
    }
  }
  UMA_HISTOGRAM_ENUMERATION("Net.AlternativeServiceTypeForRequest", type,
                            MAX_ALTERNATIVE_SERVICE_TYPE);
  return alternative_service_info;
}

AlternativeServiceInfo
HttpStreamFactoryImpl::JobController::GetAlternativeServiceInfoInternal(
    const HttpRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  GURL original_url = request_info.url;

  if (!original_url.SchemeIs(url::kHttpsScheme))
    return AlternativeServiceInfo();

  url::SchemeHostPort origin(original_url);
  HttpServerProperties& http_server_properties =
      *session_->http_server_properties();
  const AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties.GetAlternativeServiceInfos(origin);
  if (alternative_service_info_vector.empty())
    return AlternativeServiceInfo();

  bool quic_advertised = false;
  bool quic_all_broken = true;

  // First alternative service that is not marked as broken.
  AlternativeServiceInfo first_alternative_service_info;

  for (const AlternativeServiceInfo& alternative_service_info :
       alternative_service_info_vector) {
    DCHECK(IsAlternateProtocolValid(
        alternative_service_info.alternative_service().protocol));
    if (!quic_advertised &&
        alternative_service_info.alternative_service().protocol == kProtoQUIC)
      quic_advertised = true;
    if (http_server_properties.IsAlternativeServiceBroken(
            alternative_service_info.alternative_service())) {
      HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_BROKEN, false);
      continue;
    }

    // Some shared unix systems may have user home directories (like
    // http://foo.com/~mike) which allow users to emit headers.  This is a bad
    // idea already, but with Alternate-Protocol, it provides the ability for a
    // single user on a multi-user system to hijack the alternate protocol.
    // These systems also enforce ports <1024 as restricted ports.  So don't
    // allow protocol upgrades to user-controllable ports.
    const int kUnrestrictedPort = 1024;
    if (!session_->params().enable_user_alternate_protocol_ports &&
        (alternative_service_info.alternative_service().port >=
             kUnrestrictedPort &&
         origin.port() < kUnrestrictedPort))
      continue;

    if (alternative_service_info.alternative_service().protocol ==
        kProtoHTTP2) {
      if (!session_->params().enable_http2_alternative_service)
        continue;

      // Cache this entry if we don't have a non-broken Alt-Svc yet.
      if (first_alternative_service_info.alternative_service().protocol ==
          kProtoUnknown)
        first_alternative_service_info = alternative_service_info;
      continue;
    }

    DCHECK_EQ(kProtoQUIC,
              alternative_service_info.alternative_service().protocol);
    quic_all_broken = false;
    if (!session_->IsQuicEnabled())
      continue;

    if (stream_type == HttpStreamRequest::BIDIRECTIONAL_STREAM &&
        session_->params().quic_disable_bidirectional_streams) {
      continue;
    }

    if (!original_url.SchemeIs(url::kHttpsScheme))
      continue;

    // Check whether there is an existing QUIC session to use for this origin.
    HostPortPair mapped_origin(origin.host(), origin.port());
    ignore_result(ApplyHostMappingRules(original_url, &mapped_origin));
    QuicServerId server_id(mapped_origin, request_info.privacy_mode);

    HostPortPair destination(
        alternative_service_info.alternative_service().host_port_pair());
    ignore_result(ApplyHostMappingRules(original_url, &destination));

    if (session_->quic_stream_factory()->CanUseExistingSession(server_id,
                                                               destination)) {
      return alternative_service_info;
    }

    // Cache this entry if we don't have a non-broken Alt-Svc yet.
    if (first_alternative_service_info.alternative_service().protocol ==
        kProtoUnknown)
      first_alternative_service_info = alternative_service_info;
  }

  // Ask delegate to mark QUIC as broken for the origin.
  if (quic_advertised && quic_all_broken && delegate != nullptr)
    delegate->OnQuicBroken();

  return first_alternative_service_info;
}

bool HttpStreamFactoryImpl::JobController::
    ShouldCreateAlternativeProxyServerJob(
        const ProxyInfo& proxy_info,
        const GURL& url,
        ProxyServer* alternative_proxy_server) const {
  DCHECK(!alternative_proxy_server->is_valid());

  if (!enable_alternative_services_)
    return false;

  if (!can_start_alternative_proxy_job_) {
    // Either an alternative service job or an alternative proxy server job has
    // already been started.
    return false;
  }

  if (proxy_info.is_empty() || proxy_info.is_direct() || proxy_info.is_quic()) {
    // Alternative proxy server job can be created only if |job| fetches the
    // |request_| through a non-QUIC proxy.
    return false;
  }

  if (!url.SchemeIs(url::kHttpScheme)) {
    // Only HTTP URLs can be fetched through alternative proxy server, since the
    // alternative proxy server may not support fetching of URLs with other
    // schemes.
    return false;
  }

  ProxyDelegate* proxy_delegate = session_->context().proxy_delegate;
  if (!proxy_delegate)
    return false;
  proxy_delegate->GetAlternativeProxy(url, proxy_info.proxy_server(),
                                      alternative_proxy_server);

  if (!alternative_proxy_server->is_valid())
    return false;

  DCHECK(!(*alternative_proxy_server == proxy_info.proxy_server()));

  if (!alternative_proxy_server->is_https() &&
      !alternative_proxy_server->is_quic()) {
    // Alternative proxy server should be a secure server.
    return false;
  }

  if (alternative_proxy_server->is_quic()) {
    // Check that QUIC is enabled globally.
    if (!session_->IsQuicEnabled())
      return false;
  }

  return true;
}

void HttpStreamFactoryImpl::JobController::ReportAlternateProtocolUsage(
    Job* job) const {
  DCHECK(main_job_ && alternative_job_);

  bool proxy_server_used =
      alternative_job_->alternative_proxy_server().is_quic();

  if (job == main_job_.get()) {
    HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_LOST_RACE,
                                    proxy_server_used);
    return;
  }

  DCHECK_EQ(alternative_job_.get(), job);
  if (job->using_existing_quic_session()) {
    HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_NO_RACE,
                                    proxy_server_used);
    return;
  }

  HistogramAlternateProtocolUsage(ALTERNATE_PROTOCOL_USAGE_WON_RACE,
                                  proxy_server_used);
}

bool HttpStreamFactoryImpl::JobController::IsJobOrphaned(Job* job) const {
  return !request_ || (job_bound_ && bound_job_ != job);
}

int HttpStreamFactoryImpl::JobController::ReconsiderProxyAfterError(Job* job,
                                                                    int error) {
  // ReconsiderProxyAfterError() should only be called when the last job fails.
  DCHECK(!(alternative_job_ && main_job_));
  DCHECK(!pac_request_);
  DCHECK(session_);

  if (!job->should_reconsider_proxy())
    return error;

  DCHECK(!job->alternative_proxy_server().is_valid());

  // Do not bypass non-QUIC proxy on ERR_MSG_TOO_BIG.
  if (!proxy_info_.is_quic() && error == ERR_MSG_TOO_BIG)
    return error;

  if (request_info_.load_flags & LOAD_BYPASS_PROXY)
    return error;

  if (proxy_info_.is_https() && proxy_ssl_config_.send_client_cert) {
    session_->ssl_client_auth_cache()->Remove(
        proxy_info_.proxy_server().host_port_pair());
  }

  HostPortPair destination(HostPortPair::FromURL(request_info_.url));
  GURL origin_url = ApplyHostMappingRules(request_info_.url, &destination);

  int rv = session_->proxy_service()->ReconsiderProxyAfterError(
      origin_url, request_info_.method, error, &proxy_info_, io_callback_,
      &pac_request_, session_->context().proxy_delegate, net_log_);
  if (rv == OK || rv == ERR_IO_PENDING) {
    if (!job->using_quic())
      RemoveRequestFromSpdySessionRequestMap();
    // Abandon all Jobs and start over.
    job_bound_ = false;
    bound_job_ = nullptr;
    alternative_job_.reset();
    main_job_.reset();
    next_state_ = STATE_RESOLVE_PROXY_COMPLETE;
  } else {
    // If ReconsiderProxyAfterError() failed synchronously, it means
    // there was nothing left to fall-back to, so fail the transaction
    // with the last connection error we got.
    // TODO(eroman): This is a confusing contract, make it more obvious.
    rv = error;
  }
  return rv;
}

}  // namespace net
