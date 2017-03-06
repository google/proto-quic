// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_job_controller.h"

#include <memory>
#include <string>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
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
#include "net/spdy/spdy_session.h"
#include "url/url_constants.h"

namespace net {

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
    bool is_preconnect)
    : factory_(factory),
      session_(session),
      job_factory_(job_factory),
      request_(nullptr),
      delegate_(delegate),
      is_preconnect_(is_preconnect),
      alternative_job_net_error_(OK),
      job_bound_(false),
      main_job_is_blocked_(false),
      main_job_is_resumed_(false),
      bound_job_(nullptr),
      can_start_alternative_proxy_job_(false),
      privacy_mode_(PRIVACY_MODE_DISABLED),
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
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER);
}

bool HttpStreamFactoryImpl::JobController::for_websockets() {
  return factory_->for_websockets_;
}

HttpStreamFactoryImpl::Request* HttpStreamFactoryImpl::JobController::Start(
    const HttpRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    const NetLogWithSource& source_net_log,
    HttpStreamRequest::StreamType stream_type,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config) {
  DCHECK(factory_);
  DCHECK(!request_);

  privacy_mode_ = request_info.privacy_mode;

  request_ = new Request(request_info.url, this, delegate,
                         websocket_handshake_stream_create_helper,
                         source_net_log, stream_type);
  // Associates |net_log_| with |source_net_log|.
  source_net_log.AddEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND,
                          net_log_.source().ToEventParametersCallback());
  net_log_.AddEvent(NetLogEventType::HTTP_STREAM_JOB_CONTROLLER_BOUND,
                    source_net_log.source().ToEventParametersCallback());

  CreateJobs(request_info, priority, server_ssl_config, proxy_ssl_config,
             delegate, stream_type);

  return request_;
}

void HttpStreamFactoryImpl::JobController::Preconnect(
    int num_streams,
    const HttpRequestInfo& request_info,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config) {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);
  DCHECK(is_preconnect_);

  privacy_mode_ = request_info.privacy_mode;

  HostPortPair destination(HostPortPair::FromURL(request_info.url));
  GURL origin_url = ApplyHostMappingRules(request_info.url, &destination);

  const AlternativeService alternative_service = GetAlternativeServiceFor(
      request_info, nullptr, HttpStreamRequest::HTTP_STREAM);

  if (alternative_service.protocol != kProtoUnknown) {
    if (session_->params().quic_disable_preconnect_if_0rtt &&
        alternative_service.protocol == kProtoQUIC &&
        session_->quic_stream_factory()->ZeroRTTEnabledFor(QuicServerId(
            alternative_service.host_port_pair(), request_info.privacy_mode))) {
      MaybeNotifyFactoryOfCompletion();
      return;
    }
    destination = alternative_service.host_port_pair();
    ignore_result(ApplyHostMappingRules(request_info.url, &destination));
  }

  // Due to how the socket pools handle priorities and idle sockets, only IDLE
  // priority currently makes sense for preconnects. The priority for
  // preconnects is currently ignored (see RequestSocketsForPool()), but could
  // be used at some point for proxy resolution or something.
  main_job_.reset(job_factory_->CreateJob(
      this, PRECONNECT, session_, request_info, IDLE, server_ssl_config,
      proxy_ssl_config, destination, origin_url, alternative_service,
      session_->net_log()));
  main_job_->Preconnect(num_streams);
}

LoadState HttpStreamFactoryImpl::JobController::GetLoadState() const {
  DCHECK(request_);
  DCHECK(main_job_ || alternative_job_);
  if (bound_job_)
    return bound_job_->GetLoadState();

  // Just pick the first one.
  return main_job_ ? main_job_->GetLoadState()
                   : alternative_job_->GetLoadState();
}

void HttpStreamFactoryImpl::JobController::OnRequestComplete() {
  CancelJobs();
  DCHECK(request_);
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

  factory_->OnStreamReady(job->proxy_info(), privacy_mode_);

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
  request_->OnStreamReady(used_ssl_config, job->proxy_info(), stream.release());
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
                                           stream.release());
}

void HttpStreamFactoryImpl::JobController::OnWebSocketHandshakeStreamReady(
    Job* job,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    WebSocketHandshakeStreamBase* stream) {
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
                                            stream);
}

void HttpStreamFactoryImpl::JobController::OnStreamFailed(
    Job* job,
    int status,
    const SSLConfig& used_ssl_config) {
  if (job->job_type() == ALTERNATIVE) {
    DCHECK_EQ(alternative_job_.get(), job);
    OnAlternativeJobFailed(status);
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
      factory_->request_map_.erase(job);
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
    HttpStream* stream) {
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
                                       used_proxy_info, stream);
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
  return factory_->OnInitConnection(*this, proxy_info, privacy_mode_);
}

void HttpStreamFactoryImpl::JobController::OnResolveProxyComplete(
    Job* job,
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::StreamType stream_type) {
  DCHECK(job);

  ProxyServer alternative_proxy_server;
  if (!ShouldCreateAlternativeProxyServerJob(job, job->proxy_info(),
                                             request_info.url,
                                             &alternative_proxy_server)) {
    return;
  }

  DCHECK(main_job_);
  DCHECK_EQ(MAIN, job->job_type());
  DCHECK(!alternative_job_);
  DCHECK(!main_job_is_blocked_);

  HostPortPair destination(HostPortPair::FromURL(request_info.url));
  GURL origin_url = ApplyHostMappingRules(request_info.url, &destination);

  alternative_job_.reset(job_factory_->CreateJob(
      this, ALTERNATIVE, session_, request_info, priority, server_ssl_config,
      proxy_ssl_config, destination, origin_url, alternative_proxy_server,
      job->net_log().net_log()));
  AttachJob(alternative_job_.get());

  can_start_alternative_proxy_job_ = false;
  main_job_is_blocked_ = true;

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(
          &HttpStreamFactoryImpl::JobController::StartAlternativeProxyServerJob,
          ptr_factory_.GetWeakPtr()));
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

  // Cache this so we can still use it if the JobController is deleted.
  HttpStreamFactoryImpl* factory = factory_;

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

    std::unique_ptr<HttpStream> stream;
    std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_impl;

    if (for_websockets()) {
      // TODO(ricea): Re-instate this code when WebSockets over SPDY is
      // implemented.
      NOTREACHED();
    } else if (job->stream_type() == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
      bidirectional_stream_impl = job->ReleaseBidirectionalStream();
      DCHECK(bidirectional_stream_impl);
      delegate_->OnBidirectionalStreamImplReady(
          used_ssl_config, used_proxy_info,
          bidirectional_stream_impl.release());
    } else {
      stream = job->ReleaseStream();
      DCHECK(stream);
      delegate_->OnStreamReady(used_ssl_config, used_proxy_info,
                               stream.release());
    }
  }

  // Notify |factory_|. |request_| and |bounded_job_| might be deleted already.
  if (spdy_session && spdy_session->IsAvailable()) {
    factory->OnNewSpdySessionReady(spdy_session, direct, used_ssl_config,
                                   used_proxy_info, was_alpn_negotiated,
                                   negotiated_protocol, using_spdy);
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
  if (is_preconnect_ || (job_bound_ && bound_job_ != job))
    return;

  DCHECK(request_);
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
  if (is_preconnect_ || (job_bound_ && bound_job_ != job))
    return;

  DCHECK(request_);
  if (!request_->HasSpdySessionKey()) {
    RequestSet& request_set =
        factory_->spdy_session_request_map_[spdy_session_key];
    DCHECK(!base::ContainsKey(request_set, request_));
    request_set.insert(request_);
    request_->SetSpdySessionKey(spdy_session_key);
  }
}

void HttpStreamFactoryImpl::JobController::
    RemoveRequestFromSpdySessionRequestMapForJob(Job* job) {
  if (is_preconnect_ || (job_bound_ && bound_job_ != job))
    return;
  DCHECK(request_);

  RemoveRequestFromSpdySessionRequestMap();
}

void HttpStreamFactoryImpl::JobController::
    RemoveRequestFromSpdySessionRequestMap() {
  const SpdySessionKey* spdy_session_key = request_->spdy_session_key();
  if (spdy_session_key) {
    SpdySessionRequestMap& spdy_session_request_map =
        factory_->spdy_session_request_map_;
    DCHECK(base::ContainsKey(spdy_session_request_map, *spdy_session_key));
    RequestSet& request_set = spdy_session_request_map[*spdy_session_key];
    DCHECK(base::ContainsKey(request_set, request_));
    request_set.erase(request_);
    if (request_set.empty())
      spdy_session_request_map.erase(*spdy_session_key);
    request_->ResetSpdySessionKey();
  }
}

const NetLogWithSource* HttpStreamFactoryImpl::JobController::GetNetLog(
    Job* job) const {
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

size_t HttpStreamFactoryImpl::JobController::EstimateMemoryUsage() const {
  size_t estimated_size = 0;
  if (main_job_)
    estimated_size += main_job_->EstimateMemoryUsage();
  if (alternative_job_)
    estimated_size += alternative_job_->EstimateMemoryUsage();
  return estimated_size;
}

WebSocketHandshakeStreamBase::CreateHelper* HttpStreamFactoryImpl::
    JobController::websocket_handshake_stream_create_helper() {
  DCHECK(request_);
  return request_->websocket_handshake_stream_create_helper();
}

void HttpStreamFactoryImpl::JobController::CreateJobs(
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  DCHECK(!main_job_);
  DCHECK(!alternative_job_);
  HostPortPair destination(HostPortPair::FromURL(request_info.url));
  GURL origin_url = ApplyHostMappingRules(request_info.url, &destination);

  main_job_.reset(job_factory_->CreateJob(
      this, MAIN, session_, request_info, priority, server_ssl_config,
      proxy_ssl_config, destination, origin_url, net_log_.net_log()));
  AttachJob(main_job_.get());

  // Create an alternative job if alternative service is set up for this domain.
  const AlternativeService alternative_service =
      GetAlternativeServiceFor(request_info, delegate, stream_type);

  if (alternative_service.protocol != kProtoUnknown) {
    // Never share connection with other jobs for FTP requests.
    DVLOG(1) << "Selected alternative service (host: "
             << alternative_service.host_port_pair().host()
             << " port: " << alternative_service.host_port_pair().port() << ")";

    DCHECK(!request_info.url.SchemeIs(url::kFtpScheme));
    HostPortPair alternative_destination(alternative_service.host_port_pair());
    ignore_result(
        ApplyHostMappingRules(request_info.url, &alternative_destination));

    alternative_job_.reset(job_factory_->CreateJob(
        this, ALTERNATIVE, session_, request_info, priority, server_ssl_config,
        proxy_ssl_config, alternative_destination, origin_url,
        alternative_service, net_log_.net_log()));
    AttachJob(alternative_job_.get());

    main_job_is_blocked_ = true;
    alternative_job_->Start(request_->stream_type());
  } else {
    can_start_alternative_proxy_job_ = true;
  }
  // Even if |alternative_job| has already finished, it will not have notified
  // the request yet, since we defer that to the next iteration of the
  // MessageLoop, so starting |main_job_| is always safe.
  main_job_->Start(request_->stream_type());
}

void HttpStreamFactoryImpl::JobController::AttachJob(Job* job) {
  DCHECK(job);
  factory_->request_map_[job] = request_;
}

void HttpStreamFactoryImpl::JobController::BindJob(Job* job) {
  DCHECK(request_);
  DCHECK(job);
  DCHECK(job == alternative_job_.get() || job == main_job_.get());
  DCHECK(!job_bound_);
  DCHECK(!bound_job_);

  job_bound_ = true;
  bound_job_ = job;
  factory_->request_map_.erase(job);

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
  RemoveRequestFromSpdySessionRequestMap();
  if (job_bound_)
    return;
  if (alternative_job_) {
    factory_->request_map_.erase(alternative_job_.get());
    alternative_job_.reset();
  }
  if (main_job_) {
    factory_->request_map_.erase(main_job_.get());
    main_job_.reset();
  }
}

void HttpStreamFactoryImpl::JobController::OrphanUnboundJob() {
  DCHECK(request_);
  RemoveRequestFromSpdySessionRequestMap();

  DCHECK(bound_job_);
  if (bound_job_->job_type() == MAIN && alternative_job_) {
    factory_->request_map_.erase(alternative_job_.get());
    alternative_job_->Orphan();
  } else if (bound_job_->job_type() == ALTERNATIVE && main_job_) {
    // Orphan main job.
    factory_->request_map_.erase(main_job_.get());
    // If ResumeMainJob() is not executed, reset |main_job_|. Otherwise,
    // OnOrphanedJobComplete() will clean up |this| when the job completes.
    // Use |main_job_is_blocked_| and |!main_job_wait_time_.is_zero()| instead
    // of |main_job_|->is_waiting() because |main_job_| can be in proxy
    // resolution step.
    if (main_job_ && (main_job_is_blocked_ || !main_job_wait_time_.is_zero())) {
      DCHECK(alternative_job_);
      main_job_.reset();
    } else {
      main_job_->Orphan();
    }
  }
}

void HttpStreamFactoryImpl::JobController::OnJobSucceeded(Job* job) {
  // |job| should only be nullptr if we're being serviced by a late bound
  // SpdySession (one that was not created by a job in our |jobs_| set).
  if (!job) {
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

void HttpStreamFactoryImpl::JobController::OnAlternativeJobFailed(
    int net_error) {
  DCHECK_EQ(alternative_job_->job_type(), ALTERNATIVE);
  DCHECK_NE(OK, net_error);

  alternative_job_net_error_ = net_error;

  if (alternative_job_->alternative_proxy_server().is_valid()) {
    failed_alternative_proxy_server_ =
        alternative_job_->alternative_proxy_server();
  } else {
    DCHECK(!failed_alternative_proxy_server_.is_valid());
    failed_alternative_service_ = alternative_job_->alternative_service();
  }

  if (IsJobOrphaned(alternative_job_.get())) {
    // If |request_| is gone then it must have been successfully served by
    // |main_job_|.
    // If |request_| is bound to a different job, then it is being
    // successfully serverd by the main job.
    ReportBrokenAlternativeService();
  }
}

void HttpStreamFactoryImpl::JobController::ReportBrokenAlternativeService() {
  DCHECK(failed_alternative_service_.protocol != kProtoUnknown ||
         failed_alternative_proxy_server_.is_valid());
  DCHECK_NE(OK, alternative_job_net_error_);

  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.AlternateServiceFailed",
                              -alternative_job_net_error_);

  if (session_->params().quic_do_not_mark_as_broken_on_network_change &&
      (alternative_job_net_error_ == ERR_NETWORK_CHANGED ||
       alternative_job_net_error_ == ERR_INTERNET_DISCONNECTED)) {
    // No need to mark alternative service or proxy as broken.
    return;
  }

  if (failed_alternative_proxy_server_.is_valid()) {
    ProxyDelegate* proxy_delegate = session_->params().proxy_delegate;
    if (proxy_delegate) {
      proxy_delegate->OnAlternativeProxyBroken(
          failed_alternative_proxy_server_);
    }
  } else {
    HistogramBrokenAlternateProtocolLocation(
        BROKEN_ALTERNATE_PROTOCOL_LOCATION_HTTP_STREAM_FACTORY_IMPL_JOB_ALT);
    session_->http_server_properties()->MarkAlternativeServiceBroken(
        failed_alternative_service_);
  }
  session_->quic_stream_factory()->OnTcpJobCompleted(true);
}

void HttpStreamFactoryImpl::JobController::MaybeNotifyFactoryOfCompletion() {
  if (!request_ && !main_job_ && !alternative_job_) {
    DCHECK(!bound_job_);
    factory_->OnJobControllerComplete(this);
  }
}

GURL HttpStreamFactoryImpl::JobController::ApplyHostMappingRules(
    const GURL& url,
    HostPortPair* endpoint) {
  const HostMappingRules* mapping_rules = session_->params().host_mapping_rules;
  if (mapping_rules && mapping_rules->RewriteHost(endpoint)) {
    url::Replacements<char> replacements;
    const std::string port_str = base::UintToString(endpoint->port());
    replacements.SetPort(port_str.c_str(), url::Component(0, port_str.size()));
    replacements.SetHost(endpoint->host().c_str(),
                         url::Component(0, endpoint->host().size()));
    return url.ReplaceComponents(replacements);
  }
  return url;
}

bool HttpStreamFactoryImpl::JobController::IsQuicWhitelistedForHost(
    const std::string& host) {
  bool whitelist_needed = false;
  // The QUIC whitelist is not needed in QUIC versions after 30.
  if (!whitelist_needed)
    return true;

  if (session_->params().transport_security_state->IsGooglePinnedHost(host))
    return true;

  return base::ContainsKey(session_->params().quic_host_whitelist,
                           base::ToLowerASCII(host));
}

AlternativeService
HttpStreamFactoryImpl::JobController::GetAlternativeServiceFor(
    const HttpRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  AlternativeService alternative_service =
      GetAlternativeServiceForInternal(request_info, delegate, stream_type);
  AlternativeServiceType type;
  if (alternative_service.protocol == kProtoUnknown) {
    type = NO_ALTERNATIVE_SERVICE;
  } else if (alternative_service.protocol == kProtoQUIC) {
    if (request_info.url.host_piece() == alternative_service.host) {
      type = QUIC_SAME_DESTINATION;
    } else {
      type = QUIC_DIFFERENT_DESTINATION;
    }
  } else {
    if (request_info.url.host_piece() == alternative_service.host) {
      type = NOT_QUIC_SAME_DESTINATION;
    } else {
      type = NOT_QUIC_DIFFERENT_DESTINATION;
    }
  }
  UMA_HISTOGRAM_ENUMERATION("Net.AlternativeServiceTypeForRequest", type,
                            MAX_ALTERNATIVE_SERVICE_TYPE);
  return alternative_service;
}

AlternativeService
HttpStreamFactoryImpl::JobController::GetAlternativeServiceForInternal(
    const HttpRequestInfo& request_info,
    HttpStreamRequest::Delegate* delegate,
    HttpStreamRequest::StreamType stream_type) {
  GURL original_url = request_info.url;

  if (!original_url.SchemeIs(url::kHttpsScheme))
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

  // First Alt-Svc that is not marked as broken.
  AlternativeService first_alternative_service;

  for (const AlternativeService& alternative_service :
       alternative_service_vector) {
    DCHECK(IsAlternateProtocolValid(alternative_service.protocol));
    if (!quic_advertised && alternative_service.protocol == kProtoQUIC)
      quic_advertised = true;
    if (http_server_properties.IsAlternativeServiceBroken(
            alternative_service)) {
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
        (alternative_service.port >= kUnrestrictedPort &&
         origin.port() < kUnrestrictedPort))
      continue;

    if (alternative_service.protocol == kProtoHTTP2) {
      if (origin.host() != alternative_service.host &&
          !session_->params()
               .enable_http2_alternative_service_with_different_host) {
        continue;
      }

      // Cache this entry if we don't have a non-broken Alt-Svc yet.
      if (first_alternative_service.protocol == kProtoUnknown)
        first_alternative_service = alternative_service;
      continue;
    }

    DCHECK_EQ(kProtoQUIC, alternative_service.protocol);
    if (origin.host() != alternative_service.host &&
        !session_->params()
             .enable_quic_alternative_service_with_different_host) {
      continue;
    }

    quic_all_broken = false;
    if (!session_->IsQuicEnabled())
      continue;

    if (!IsQuicWhitelistedForHost(origin.host()))
      continue;

    if (stream_type == HttpStreamRequest::BIDIRECTIONAL_STREAM &&
        session_->params().quic_disable_bidirectional_streams) {
      continue;
    }

    if (session_->quic_stream_factory()->IsQuicDisabled())
      continue;

    if (!original_url.SchemeIs(url::kHttpsScheme))
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
    if (first_alternative_service.protocol == kProtoUnknown)
      first_alternative_service = alternative_service;
  }

  // Ask delegate to mark QUIC as broken for the origin.
  if (quic_advertised && quic_all_broken && delegate != nullptr)
    delegate->OnQuicBroken();

  return first_alternative_service;
}

bool HttpStreamFactoryImpl::JobController::
    ShouldCreateAlternativeProxyServerJob(
        Job* job,
        const ProxyInfo& proxy_info,
        const GURL& url,
        ProxyServer* alternative_proxy_server) const {
  DCHECK(!alternative_proxy_server->is_valid());
  if (!can_start_alternative_proxy_job_) {
    // Either an alternative service job or an alternative proxy server job has
    // already been started.
    return false;
  }

  if (job->job_type() == ALTERNATIVE) {
    // If |job| is using alternative service, then alternative proxy server
    // should not be used.
    return false;
  }

  if (is_preconnect_ || job->job_type() == PRECONNECT) {
    // Preconnects should be fetched using only the main job to keep the
    // resource utilization down.
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

  ProxyDelegate* proxy_delegate = session_->params().proxy_delegate;
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
    // Check that QUIC is enabled globally, and it is not disabled.
    if (!session_->IsQuicEnabled() ||
        session_->quic_stream_factory()->IsQuicDisabled()) {
      return false;
    }
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

void HttpStreamFactoryImpl::JobController::StartAlternativeProxyServerJob() {
  if (!alternative_job_ || !request_)
    return;
  DCHECK(alternative_job_->alternative_proxy_server().is_valid());
  alternative_job_->Start(request_->stream_type());
}

bool HttpStreamFactoryImpl::JobController::IsJobOrphaned(Job* job) const {
  return !request_ || (job_bound_ && bound_job_ != job);
}

}  // namespace net
