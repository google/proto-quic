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
    HttpStreamFactoryImpl* factory,
    HttpStreamRequest::Delegate* delegate,
    WebSocketHandshakeStreamBase::CreateHelper*
        websocket_handshake_stream_create_helper,
    const BoundNetLog& net_log,
    StreamType stream_type)
    : url_(url),
      factory_(factory),
      websocket_handshake_stream_create_helper_(
          websocket_handshake_stream_create_helper),
      delegate_(delegate),
      net_log_(net_log),
      completed_(false),
      was_npn_negotiated_(false),
      protocol_negotiated_(kProtoUnknown),
      using_spdy_(false),
      stream_type_(stream_type) {
  DCHECK(factory_);
  DCHECK(delegate_);

  net_log_.BeginEvent(NetLog::TYPE_HTTP_STREAM_REQUEST);
}

HttpStreamFactoryImpl::Request::~Request() {
  if (bound_job_.get())
    DCHECK(jobs_.empty());

  net_log_.EndEvent(NetLog::TYPE_HTTP_STREAM_REQUEST);

  CancelJobs();
}

void HttpStreamFactoryImpl::Request::SetSpdySessionKey(
    const SpdySessionKey& spdy_session_key) {
  CHECK(!spdy_session_key_.get());
  spdy_session_key_.reset(new SpdySessionKey(spdy_session_key));
  RequestSet& request_set =
      factory_->spdy_session_request_map_[spdy_session_key];
  DCHECK(!ContainsKey(request_set, this));
  request_set.insert(this);
}

void HttpStreamFactoryImpl::Request::AttachJob(Job* job) {
  DCHECK(job);
  jobs_.insert(job);
  factory_->request_map_[job] = this;
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
    Job* job,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpStream* stream) {
  DCHECK(!factory_->for_websockets_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, stream_type_);
  DCHECK(stream);
  DCHECK(completed_);

  OnJobSucceeded(job);
  delegate_->OnStreamReady(used_ssl_config, used_proxy_info, stream);
}

void HttpStreamFactoryImpl::Request::OnBidirectionalStreamImplReady(
    Job* job,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    BidirectionalStreamImpl* stream_job) {
  DCHECK(!factory_->for_websockets_);
  DCHECK_EQ(HttpStreamRequest::BIDIRECTIONAL_STREAM, stream_type_);
  DCHECK(stream_job);
  DCHECK(completed_);

  OnJobSucceeded(job);
  delegate_->OnBidirectionalStreamImplReady(used_ssl_config, used_proxy_info,
                                            stream_job);
}

void HttpStreamFactoryImpl::Request::OnWebSocketHandshakeStreamReady(
    Job* job,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    WebSocketHandshakeStreamBase* stream) {
  DCHECK(factory_->for_websockets_);
  DCHECK_EQ(HttpStreamRequest::HTTP_STREAM, stream_type_);
  DCHECK(stream);
  DCHECK(completed_);

  OnJobSucceeded(job);
  delegate_->OnWebSocketHandshakeStreamReady(
      used_ssl_config, used_proxy_info, stream);
}

void HttpStreamFactoryImpl::Request::OnStreamFailed(
    Job* job,
    int status,
    const SSLConfig& used_ssl_config,
    SSLFailureState ssl_failure_state) {
  DCHECK_NE(OK, status);
  DCHECK(job);
  if (!bound_job_.get()) {
    if (jobs_.size() > 1) {
      // Hey, we've got other jobs! Maybe one of them will succeed, let's just
      // ignore this failure.
      jobs_.erase(job);
      factory_->request_map_.erase(job);
      // Notify all the other jobs that this one failed.
      for (std::set<Job*>::iterator it = jobs_.begin(); it != jobs_.end(); ++it)
        (*it)->MarkOtherJobComplete(*job);
      delete job;
      return;
    } else {
      BindJob(job);
    }
  } else {
    DCHECK(jobs_.empty());
  }
  delegate_->OnStreamFailed(status, used_ssl_config, ssl_failure_state);
}

void HttpStreamFactoryImpl::Request::OnCertificateError(
    Job* job,
    int status,
    const SSLConfig& used_ssl_config,
    const SSLInfo& ssl_info) {
  DCHECK_NE(OK, status);
  if (!bound_job_.get())
    BindJob(job);
  else
    DCHECK(jobs_.empty());
  delegate_->OnCertificateError(status, used_ssl_config, ssl_info);
}

void HttpStreamFactoryImpl::Request::OnNeedsProxyAuth(
    Job* job,
    const HttpResponseInfo& proxy_response,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  if (!bound_job_.get())
    BindJob(job);
  else
    DCHECK(jobs_.empty());
  delegate_->OnNeedsProxyAuth(
      proxy_response, used_ssl_config, used_proxy_info, auth_controller);
}

void HttpStreamFactoryImpl::Request::OnNeedsClientAuth(
    Job* job,
    const SSLConfig& used_ssl_config,
    SSLCertRequestInfo* cert_info) {
  if (!bound_job_.get())
    BindJob(job);
  else
    DCHECK(jobs_.empty());
  delegate_->OnNeedsClientAuth(used_ssl_config, cert_info);
}

void HttpStreamFactoryImpl::Request::OnHttpsProxyTunnelResponse(
    Job *job,
    const HttpResponseInfo& response_info,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpStream* stream) {
  if (!bound_job_.get())
    BindJob(job);
  else
    DCHECK(jobs_.empty());
  delegate_->OnHttpsProxyTunnelResponse(
      response_info, used_ssl_config, used_proxy_info, stream);
}

int HttpStreamFactoryImpl::Request::RestartTunnelWithProxyAuth(
    const AuthCredentials& credentials) {
  DCHECK(bound_job_.get());
  return bound_job_->RestartTunnelWithProxyAuth(credentials);
}

void HttpStreamFactoryImpl::Request::SetPriority(RequestPriority priority) {
  for (std::set<HttpStreamFactoryImpl::Job*>::const_iterator it = jobs_.begin();
       it != jobs_.end(); ++it) {
    (*it)->SetPriority(priority);
  }
  if (bound_job_)
    bound_job_->SetPriority(priority);
}

LoadState HttpStreamFactoryImpl::Request::GetLoadState() const {
  if (bound_job_.get())
    return bound_job_->GetLoadState();
  DCHECK(!jobs_.empty());

  // Just pick the first one.
  return (*jobs_.begin())->GetLoadState();
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

void
HttpStreamFactoryImpl::Request::RemoveRequestFromSpdySessionRequestMap() {
  if (spdy_session_key_.get()) {
    SpdySessionRequestMap& spdy_session_request_map =
        factory_->spdy_session_request_map_;
    DCHECK(ContainsKey(spdy_session_request_map, *spdy_session_key_));
    RequestSet& request_set =
        spdy_session_request_map[*spdy_session_key_];
    DCHECK(ContainsKey(request_set, this));
    request_set.erase(this);
    if (request_set.empty())
      spdy_session_request_map.erase(*spdy_session_key_);
    spdy_session_key_.reset();
  }
}

bool HttpStreamFactoryImpl::Request::HasSpdySessionKey() const {
  return spdy_session_key_.get() != NULL;
}

// TODO(jgraettinger): Currently, HttpStreamFactoryImpl::Job notifies a
// Request that the session is ready, which in turn notifies it's delegate,
// and then it notifies HttpStreamFactoryImpl so that /other/ requests may
// be woken, but only if the spdy_session is still okay. This is tough to grok.
// Instead, see if Job can notify HttpStreamFactoryImpl only, and have one
// path for notifying any requests waiting for the session (including the
// request which spawned it).
void HttpStreamFactoryImpl::Request::OnNewSpdySessionReady(
    Job* job,
    std::unique_ptr<HttpStream> stream,
    std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_impl,
    const base::WeakPtr<SpdySession>& spdy_session,
    bool direct) {
  DCHECK(job);
  DCHECK(job->using_spdy());

  // Note: |spdy_session| may be NULL. In that case, |delegate_| should still
  // receive |stream| so the error propagates up correctly, however there is no
  // point in broadcasting |spdy_session| to other requests.

  // The first case is the usual case.
  if (!bound_job_.get()) {
    BindJob(job);
  } else {  // This is the case for HTTPS proxy tunneling.
    DCHECK_EQ(bound_job_.get(), job);
    DCHECK(jobs_.empty());
  }

  // Cache these values in case the job gets deleted.
  const SSLConfig used_ssl_config = job->server_ssl_config();
  const ProxyInfo used_proxy_info = job->proxy_info();
  const bool was_npn_negotiated = job->was_npn_negotiated();
  const NextProto protocol_negotiated =
      job->protocol_negotiated();
  const bool using_spdy = job->using_spdy();
  const BoundNetLog net_log = job->net_log();

  Complete(was_npn_negotiated, protocol_negotiated, using_spdy);

  // Cache this so we can still use it if the request is deleted.
  HttpStreamFactoryImpl* factory = factory_;
  if (factory->for_websockets_) {
    // TODO(ricea): Re-instate this code when WebSockets over SPDY is
    // implemented.
    NOTREACHED();
  } else if (stream_type_ == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
    DCHECK(bidirectional_stream_impl);
    DCHECK(!stream);
    delegate_->OnBidirectionalStreamImplReady(
        job->server_ssl_config(), job->proxy_info(),
        bidirectional_stream_impl.release());
  } else {
    DCHECK(!bidirectional_stream_impl);
    DCHECK(stream);
    delegate_->OnStreamReady(job->server_ssl_config(), job->proxy_info(),
                             stream.release());
  }
  // |this| may be deleted after this point.
  if (spdy_session && spdy_session->IsAvailable()) {
    factory->OnNewSpdySessionReady(spdy_session,
                                   direct,
                                   used_ssl_config,
                                   used_proxy_info,
                                   was_npn_negotiated,
                                   protocol_negotiated,
                                   using_spdy,
                                   net_log);
  }
}

void HttpStreamFactoryImpl::Request::AddConnectionAttempts(
    const ConnectionAttempts& attempts) {
  for (const auto& attempt : attempts)
    connection_attempts_.push_back(attempt);
}

void HttpStreamFactoryImpl::Request::BindJob(Job* job) {
  DCHECK(job);
  DCHECK(!bound_job_.get());
  DCHECK(ContainsKey(jobs_, job));
  bound_job_.reset(job);
  jobs_.erase(job);
  factory_->request_map_.erase(job);

  net_log_.AddEvent(NetLog::TYPE_HTTP_STREAM_REQUEST_BOUND_TO_JOB,
                    job->net_log().source().ToEventParametersCallback());
  job->net_log().AddEvent(NetLog::TYPE_HTTP_STREAM_JOB_BOUND_TO_REQUEST,
                          net_log_.source().ToEventParametersCallback());

  OrphanJobs();
}

void HttpStreamFactoryImpl::Request::OrphanJobs() {
  RemoveRequestFromSpdySessionRequestMap();

  std::set<Job*> tmp;
  tmp.swap(jobs_);

  for (Job* job : tmp)
    factory_->OrphanJob(job, this);
}

void HttpStreamFactoryImpl::Request::CancelJobs() {
  RemoveRequestFromSpdySessionRequestMap();

  std::set<Job*> tmp;
  tmp.swap(jobs_);

  for (Job* job : tmp) {
    factory_->request_map_.erase(job);
    delete job;
  }
}

void HttpStreamFactoryImpl::Request::OnJobSucceeded(Job* job) {
  // |job| should only be NULL if we're being serviced by a late bound
  // SpdySession (one that was not created by a job in our |jobs_| set).
  if (!job) {
    DCHECK(!bound_job_.get());
    DCHECK(!jobs_.empty());
    // NOTE(willchan): We do *NOT* call OrphanJobs() here. The reason is because
    // we *WANT* to cancel the unnecessary Jobs from other requests if another
    // Job completes first.
    // TODO(mbelshe): Revisit this when we implement ip connection pooling of
    // SpdySessions. Do we want to orphan the jobs for a different hostname so
    // they complete? Or do we want to prevent connecting a new SpdySession if
    // we've already got one available for a different hostname where the ip
    // address matches up?
    CancelJobs();
    return;
  }
  if (!bound_job_.get()) {
    if (jobs_.size() > 1)
      job->ReportJobSucceededForRequest();
    // Notify all the other jobs that this one succeeded.
    for (std::set<Job*>::iterator it = jobs_.begin(); it != jobs_.end(); ++it) {
      if (*it != job) {
        (*it)->MarkOtherJobComplete(*job);
      }
    }
    // We may have other jobs in |jobs_|. For example, if we start multiple jobs
    // for Alternate-Protocol.
    BindJob(job);
    return;
  }
  DCHECK(jobs_.empty());
}

}  // namespace net
