// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_job.h"

#include <algorithm>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/profiler/scoped_tracker.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/port_util.h"
#include "net/base/proxy_delegate.h"
#include "net/base/trace_constants.h"
#include "net/cert/cert_verifier.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_network_session.h"
#include "net/http/http_proxy_client_socket.h"
#include "net/http/http_proxy_client_socket_pool.h"
#include "net/http/http_request_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_factory_impl_request.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/quic/chromium/quic_http_stream.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/socks_client_socket_pool.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/ssl_client_socket_pool.h"
#include "net/spdy/bidirectional_stream_spdy_impl.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "url/url_constants.h"

namespace net {

namespace {

void DoNothingAsyncCallback(int result) {}
void RecordChannelIDKeyMatch(SSLClientSocket* ssl_socket,
                             ChannelIDService* channel_id_service,
                             std::string host) {
  SSLInfo ssl_info;
  ssl_socket->GetSSLInfo(&ssl_info);
  if (!ssl_info.channel_id_sent)
    return;
  std::unique_ptr<crypto::ECPrivateKey> request_key;
  ChannelIDService::Request request;
  int result = channel_id_service->GetOrCreateChannelID(
      host, &request_key, base::Bind(&DoNothingAsyncCallback), &request);
  // GetOrCreateChannelID only returns ERR_IO_PENDING before its first call
  // (over the lifetime of the ChannelIDService) has completed or if it is
  // creating a new key. The key that is being looked up here should already
  // have been looked up before the channel ID was sent on the ssl socket, so
  // the expectation is that this call will return synchronously. If this does
  // return ERR_IO_PENDING, treat that as any other lookup failure and cancel
  // the async request.
  if (result == ERR_IO_PENDING)
    request.Cancel();
  crypto::ECPrivateKey* socket_key = ssl_socket->GetChannelIDKey();

  // This enum is used for an UMA histogram - do not change or re-use values.
  enum {
    NO_KEYS = 0,
    MATCH = 1,
    SOCKET_KEY_MISSING = 2,
    REQUEST_KEY_MISSING = 3,
    KEYS_DIFFER = 4,
    KEY_LOOKUP_ERROR = 5,
    KEY_MATCH_MAX
  } match;
  if (result != OK) {
    match = KEY_LOOKUP_ERROR;
  } else if (!socket_key && !request_key) {
    match = NO_KEYS;
  } else if (!socket_key) {
    match = SOCKET_KEY_MISSING;
  } else if (!request_key) {
    match = REQUEST_KEY_MISSING;
  } else {
    match = KEYS_DIFFER;
    std::string raw_socket_key, raw_request_key;
    if (socket_key->ExportRawPublicKey(&raw_socket_key) &&
        request_key->ExportRawPublicKey(&raw_request_key) &&
        raw_socket_key == raw_request_key) {
      match = MATCH;
    }
  }
  UMA_HISTOGRAM_ENUMERATION("Net.TokenBinding.KeyMatch", match, KEY_MATCH_MAX);
}

}  // namespace

// Returns parameters associated with the start of a HTTP stream job.
std::unique_ptr<base::Value> NetLogHttpStreamJobCallback(
    const NetLogSource& source,
    const GURL* original_url,
    const GURL* url,
    const AlternativeService* alternative_service,
    RequestPriority priority,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  if (source.IsValid())
    source.AddToEventParameters(dict.get());
  dict->SetString("original_url", original_url->GetOrigin().spec());
  dict->SetString("url", url->GetOrigin().spec());
  dict->SetString("alternative_service", alternative_service->ToString());
  dict->SetString("priority", RequestPriorityToString(priority));
  return std::move(dict);
}

// Returns parameters associated with the Proto (with NPN negotiation) of a HTTP
// stream.
std::unique_ptr<base::Value> NetLogHttpStreamProtoCallback(
    NextProto negotiated_protocol,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  dict->SetString("proto", NextProtoToString(negotiated_protocol));
  return std::move(dict);
}

HttpStreamFactoryImpl::Job::Job(Delegate* delegate,
                                JobType job_type,
                                HttpNetworkSession* session,
                                const HttpRequestInfo& request_info,
                                RequestPriority priority,
                                const SSLConfig& server_ssl_config,
                                const SSLConfig& proxy_ssl_config,
                                HostPortPair destination,
                                GURL origin_url,
                                NetLog* net_log)
    : Job(delegate,
          job_type,
          session,
          request_info,
          priority,
          server_ssl_config,
          proxy_ssl_config,
          destination,
          origin_url,
          AlternativeService(),
          ProxyServer(),
          net_log) {}

HttpStreamFactoryImpl::Job::Job(Delegate* delegate,
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
                                NetLog* net_log)
    : request_info_(request_info),
      priority_(priority),
      server_ssl_config_(server_ssl_config),
      proxy_ssl_config_(proxy_ssl_config),
      net_log_(
          NetLogWithSource::Make(net_log, NetLogSourceType::HTTP_STREAM_JOB)),
      io_callback_(base::Bind(&Job::OnIOComplete, base::Unretained(this))),
      connection_(new ClientSocketHandle),
      session_(session),
      next_state_(STATE_NONE),
      pac_request_(NULL),
      destination_(destination),
      origin_url_(origin_url),
      alternative_service_(alternative_service),
      alternative_proxy_server_(alternative_proxy_server),
      delegate_(delegate),
      job_type_(job_type),
      using_ssl_(false),
      using_spdy_(false),
      using_quic_(false),
      quic_request_(session_->quic_stream_factory()),
      using_existing_quic_session_(false),
      establishing_tunnel_(false),
      was_alpn_negotiated_(false),
      negotiated_protocol_(kProtoUnknown),
      num_streams_(0),
      spdy_session_direct_(false),
      stream_type_(HttpStreamRequest::BIDIRECTIONAL_STREAM),
      ptr_factory_(this) {
  DCHECK(session);
  // The job can't have alternative service and alternative proxy server set at
  // the same time since alternative services are used for requests that are
  // fetched directly, while the alternative proxy server is used for requests
  // that should be fetched using proxy.
  DCHECK(alternative_service_.protocol == kProtoUnknown ||
         !alternative_proxy_server_.is_valid());
  DCHECK(!alternative_proxy_server_.is_valid() ||
         !(IsSpdyAlternative() || IsQuicAlternative()));
  // If either the alternative service protocol is specified or if the
  // alternative proxy server is valid, then the job type must be set to
  // either ALTERNATIVE or PRECONNECT.
  DCHECK((alternative_service_.protocol == kProtoUnknown &&
          !alternative_proxy_server_.is_valid()) ||
         (job_type_ == ALTERNATIVE || job_type_ == PRECONNECT));
  // If the alternative proxy server is valid, then the job type must be
  // set to ALTERNATIVE.
  DCHECK(!alternative_proxy_server_.is_valid() || job_type_ == ALTERNATIVE);

  if (IsSpdyAlternative()) {
    DCHECK(origin_url_.SchemeIs(url::kHttpsScheme));
  }
  if (IsQuicAlternative()) {
    DCHECK(session_->IsQuicEnabled());
    using_quic_ = true;
  }
}

HttpStreamFactoryImpl::Job::~Job() {
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_JOB);

  // When we're in a partially constructed state, waiting for the user to
  // provide certificate handling information or authentication, we can't reuse
  // this stream at all.
  if (next_state_ == STATE_WAITING_USER_ACTION) {
    connection_->socket()->Disconnect();
    connection_.reset();
  }

  if (pac_request_)
    session_->proxy_service()->CancelPacRequest(pac_request_);

  // The stream could be in a partial state.  It is not reusable.
  if (stream_.get() && next_state_ != STATE_DONE)
    stream_->Close(true /* not reusable */);
}

void HttpStreamFactoryImpl::Job::Start(
    HttpStreamRequest::StreamType stream_type) {
  stream_type_ = stream_type;
  StartInternal();
}

int HttpStreamFactoryImpl::Job::Preconnect(int num_streams) {
  DCHECK_GT(num_streams, 0);
  HttpServerProperties* http_server_properties =
      session_->http_server_properties();
  if (http_server_properties &&
      http_server_properties->SupportsRequestPriority(
          url::SchemeHostPort(request_info_.url))) {
    num_streams_ = 1;
  } else {
    num_streams_ = num_streams;
  }
  return StartInternal();
}

int HttpStreamFactoryImpl::Job::RestartTunnelWithProxyAuth(
    const AuthCredentials& credentials) {
  DCHECK(establishing_tunnel_);
  next_state_ = STATE_RESTART_TUNNEL_AUTH;
  stream_.reset();
  return RunLoop(OK);
}

LoadState HttpStreamFactoryImpl::Job::GetLoadState() const {
  switch (next_state_) {
    case STATE_RESOLVE_PROXY_COMPLETE:
      return session_->proxy_service()->GetLoadState(pac_request_);
    case STATE_INIT_CONNECTION_COMPLETE:
    case STATE_CREATE_STREAM_COMPLETE:
      return using_quic_ ? LOAD_STATE_CONNECTING : connection_->GetLoadState();
    default:
      return LOAD_STATE_IDLE;
  }
}

void HttpStreamFactoryImpl::Job::Resume() {
  DCHECK_EQ(job_type_, MAIN);
  DCHECK_EQ(next_state_, STATE_WAIT_COMPLETE);
  OnIOComplete(OK);
}

void HttpStreamFactoryImpl::Job::Orphan() {
  net_log_.AddEvent(NetLogEventType::HTTP_STREAM_JOB_ORPHANED);

  if (delegate_->for_websockets()) {
    // We cancel this job because a WebSocketHandshakeStream can't be created
    // without a WebSocketHandshakeStreamBase::CreateHelper which is stored in
    // the Request class and isn't retrievable by this job.
    if (connection_ && connection_->socket()) {
      connection_->socket()->Disconnect();
    }
    delegate_->OnOrphanedJobComplete(this);
  }
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::SetPriority(RequestPriority priority) {
  priority_ = priority;
  // TODO(akalin): Propagate this to |connection_| and maybe the
  // preconnect state.
}

bool HttpStreamFactoryImpl::Job::was_alpn_negotiated() const {
  return was_alpn_negotiated_;
}

NextProto HttpStreamFactoryImpl::Job::negotiated_protocol() const {
  return negotiated_protocol_;
}

bool HttpStreamFactoryImpl::Job::using_spdy() const {
  return using_spdy_;
}

const SSLConfig& HttpStreamFactoryImpl::Job::server_ssl_config() const {
  return server_ssl_config_;
}

const SSLConfig& HttpStreamFactoryImpl::Job::proxy_ssl_config() const {
  return proxy_ssl_config_;
}

const ProxyInfo& HttpStreamFactoryImpl::Job::proxy_info() const {
  return proxy_info_;
}

void HttpStreamFactoryImpl::Job::GetSSLInfo() {
  DCHECK(using_ssl_);
  DCHECK(!establishing_tunnel_);
  DCHECK(connection_.get() && connection_->socket());
  SSLClientSocket* ssl_socket =
      static_cast<SSLClientSocket*>(connection_->socket());
  ssl_socket->GetSSLInfo(&ssl_info_);
}

SpdySessionKey HttpStreamFactoryImpl::Job::GetSpdySessionKey() const {
  // In the case that we're using an HTTPS proxy for an HTTP url,
  // we look for a SPDY session *to* the proxy, instead of to the
  // origin server.
  if (IsHttpsProxyAndHttpUrl()) {
    return SpdySessionKey(proxy_info_.proxy_server().host_port_pair(),
                          ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  }
  return SpdySessionKey(destination_, proxy_info_.proxy_server(),
                        request_info_.privacy_mode);
}

bool HttpStreamFactoryImpl::Job::CanUseExistingSpdySession() const {
  // We need to make sure that if a spdy session was created for
  // https://somehost/ that we don't use that session for http://somehost:443/.
  // The only time we can use an existing session is if the request URL is
  // https (the normal case) or if we're connection to a SPDY proxy.
  // https://crbug.com/133176
  // TODO(ricea): Add "wss" back to this list when SPDY WebSocket support is
  // working.
  return origin_url_.SchemeIs(url::kHttpsScheme) ||
         proxy_info_.proxy_server().is_https();
}

void HttpStreamFactoryImpl::Job::OnStreamReadyCallback() {
  DCHECK(stream_.get());
  DCHECK_NE(job_type_, PRECONNECT);
  DCHECK(!delegate_->for_websockets());

  MaybeCopyConnectionAttemptsFromSocketOrHandle();

  delegate_->OnStreamReady(this, server_ssl_config_);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnWebSocketHandshakeStreamReadyCallback() {
  DCHECK(websocket_stream_);
  DCHECK_NE(job_type_, PRECONNECT);
  DCHECK(delegate_->for_websockets());

  MaybeCopyConnectionAttemptsFromSocketOrHandle();

  delegate_->OnWebSocketHandshakeStreamReady(
      this, server_ssl_config_, proxy_info_, websocket_stream_.release());
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnBidirectionalStreamImplReadyCallback() {
  DCHECK(bidirectional_stream_impl_);

  MaybeCopyConnectionAttemptsFromSocketOrHandle();

  delegate_->OnBidirectionalStreamImplReady(this, server_ssl_config_,
                                            proxy_info_);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnNewSpdySessionReadyCallback() {
  DCHECK(stream_.get() || bidirectional_stream_impl_.get());
  DCHECK_NE(job_type_, PRECONNECT);
  DCHECK(using_spdy());
  // Note: an event loop iteration has passed, so |new_spdy_session_| may be
  // NULL at this point if the SpdySession closed immediately after creation.
  base::WeakPtr<SpdySession> spdy_session = new_spdy_session_;
  new_spdy_session_.reset();

  MaybeCopyConnectionAttemptsFromSocketOrHandle();

  delegate_->OnNewSpdySessionReady(this, spdy_session, spdy_session_direct_);

  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnStreamFailedCallback(int result) {
  DCHECK_NE(job_type_, PRECONNECT);

  MaybeCopyConnectionAttemptsFromSocketOrHandle();

  delegate_->OnStreamFailed(this, result, server_ssl_config_);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnCertificateErrorCallback(
    int result, const SSLInfo& ssl_info) {
  DCHECK_NE(job_type_, PRECONNECT);

  MaybeCopyConnectionAttemptsFromSocketOrHandle();

  delegate_->OnCertificateError(this, result, server_ssl_config_, ssl_info);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnNeedsProxyAuthCallback(
    const HttpResponseInfo& response,
    HttpAuthController* auth_controller) {
  DCHECK_NE(job_type_, PRECONNECT);

  delegate_->OnNeedsProxyAuth(this, response, server_ssl_config_, proxy_info_,
                              auth_controller);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnNeedsClientAuthCallback(
    SSLCertRequestInfo* cert_info) {
  DCHECK_NE(job_type_, PRECONNECT);

  delegate_->OnNeedsClientAuth(this, server_ssl_config_, cert_info);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnHttpsProxyTunnelResponseCallback(
    const HttpResponseInfo& response_info,
    HttpStream* stream) {
  DCHECK_NE(job_type_, PRECONNECT);

  delegate_->OnHttpsProxyTunnelResponse(this, response_info, server_ssl_config_,
                                        proxy_info_, stream);
  // |this| may be deleted after this call.
}

void HttpStreamFactoryImpl::Job::OnPreconnectsComplete() {
  DCHECK(!new_spdy_session_);

  if (new_spdy_session_.get()) {
    delegate_->OnNewSpdySessionReady(this, new_spdy_session_,
                                     spdy_session_direct_);
  }
  delegate_->OnPreconnectsComplete(this);
  // |this| may be deleted after this call.
}

// static
int HttpStreamFactoryImpl::Job::OnHostResolution(
    SpdySessionPool* spdy_session_pool,
    const SpdySessionKey& spdy_session_key,
    const GURL& origin_url,
    const AddressList& addresses,
    const NetLogWithSource& net_log) {
  // It is OK to dereference spdy_session_pool, because the
  // ClientSocketPoolManager will be destroyed in the same callback that
  // destroys the SpdySessionPool.
  return spdy_session_pool->FindAvailableSession(spdy_session_key, origin_url,
                                                 net_log)
             ? ERR_SPDY_SESSION_ALREADY_EXISTS
             : OK;
}

void HttpStreamFactoryImpl::Job::OnIOComplete(int result) {
  TRACE_EVENT0(kNetTracingCategory, "HttpStreamFactoryImpl::Job::OnIOComplete");
  RunLoop(result);
}

int HttpStreamFactoryImpl::Job::RunLoop(int result) {
  TRACE_EVENT0(kNetTracingCategory, "HttpStreamFactoryImpl::Job::RunLoop");
  result = DoLoop(result);

  if (result == ERR_IO_PENDING)
    return result;

  if (job_type_ == PRECONNECT) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&HttpStreamFactoryImpl::Job::OnPreconnectsComplete,
                   ptr_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  }

  if (IsCertificateError(result)) {
    // Retrieve SSL information from the socket.
    GetSSLInfo();

    next_state_ = STATE_WAITING_USER_ACTION;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&HttpStreamFactoryImpl::Job::OnCertificateErrorCallback,
                   ptr_factory_.GetWeakPtr(), result, ssl_info_));
    return ERR_IO_PENDING;
  }

  switch (result) {
    case ERR_PROXY_AUTH_REQUESTED: {
      UMA_HISTOGRAM_BOOLEAN("Net.ProxyAuthRequested.HasConnection",
                            connection_.get() != NULL);
      if (!connection_.get())
        return ERR_PROXY_AUTH_REQUESTED_WITH_NO_CONNECTION;
      CHECK(connection_->socket());
      CHECK(establishing_tunnel_);

      next_state_ = STATE_WAITING_USER_ACTION;
      ProxyClientSocket* proxy_socket =
          static_cast<ProxyClientSocket*>(connection_->socket());
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::Bind(&Job::OnNeedsProxyAuthCallback, ptr_factory_.GetWeakPtr(),
                     *proxy_socket->GetConnectResponseInfo(),
                     base::RetainedRef(proxy_socket->GetAuthController())));
      return ERR_IO_PENDING;
    }

    case ERR_SSL_CLIENT_AUTH_CERT_NEEDED:
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::Bind(
              &Job::OnNeedsClientAuthCallback, ptr_factory_.GetWeakPtr(),
              base::RetainedRef(
                  connection_->ssl_error_response_info().cert_request_info)));
      return ERR_IO_PENDING;

    case ERR_HTTPS_PROXY_TUNNEL_RESPONSE: {
      DCHECK(connection_.get());
      DCHECK(connection_->socket());
      DCHECK(establishing_tunnel_);

      ProxyClientSocket* proxy_socket =
          static_cast<ProxyClientSocket*>(connection_->socket());
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&Job::OnHttpsProxyTunnelResponseCallback,
                                ptr_factory_.GetWeakPtr(),
                                *proxy_socket->GetConnectResponseInfo(),
                                proxy_socket->CreateConnectResponseStream()));
      return ERR_IO_PENDING;
    }

    case OK:
      next_state_ = STATE_DONE;
      if (new_spdy_session_.get()) {
        base::ThreadTaskRunnerHandle::Get()->PostTask(
            FROM_HERE, base::Bind(&Job::OnNewSpdySessionReadyCallback,
                                  ptr_factory_.GetWeakPtr()));
      } else if (delegate_->for_websockets()) {
        DCHECK(websocket_stream_);
        base::ThreadTaskRunnerHandle::Get()->PostTask(
            FROM_HERE, base::Bind(&Job::OnWebSocketHandshakeStreamReadyCallback,
                                  ptr_factory_.GetWeakPtr()));
      } else if (stream_type_ == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
        if (!bidirectional_stream_impl_) {
          base::ThreadTaskRunnerHandle::Get()->PostTask(
              FROM_HERE, base::Bind(&Job::OnStreamFailedCallback,
                                    ptr_factory_.GetWeakPtr(), ERR_FAILED));
        } else {
          base::ThreadTaskRunnerHandle::Get()->PostTask(
              FROM_HERE,
              base::Bind(&Job::OnBidirectionalStreamImplReadyCallback,
                         ptr_factory_.GetWeakPtr()));
        }
      } else {
        DCHECK(stream_.get());
        base::ThreadTaskRunnerHandle::Get()->PostTask(
            FROM_HERE,
            base::Bind(&Job::OnStreamReadyCallback, ptr_factory_.GetWeakPtr()));
      }
      return ERR_IO_PENDING;

    default:
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&Job::OnStreamFailedCallback,
                                ptr_factory_.GetWeakPtr(), result));
      return ERR_IO_PENDING;
  }
}

int HttpStreamFactoryImpl::Job::DoLoop(int result) {
  DCHECK_NE(next_state_, STATE_NONE);
  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_START:
        DCHECK_EQ(OK, rv);
        rv = DoStart();
        break;
      case STATE_RESOLVE_PROXY:
        DCHECK_EQ(OK, rv);
        rv = DoResolveProxy();
        break;
      case STATE_RESOLVE_PROXY_COMPLETE:
        rv = DoResolveProxyComplete(rv);
        break;
      case STATE_WAIT:
        DCHECK_EQ(OK, rv);
        rv = DoWait();
        break;
      case STATE_WAIT_COMPLETE:
        rv = DoWaitComplete(rv);
        break;
      case STATE_INIT_CONNECTION:
        DCHECK_EQ(OK, rv);
        rv = DoInitConnection();
        break;
      case STATE_INIT_CONNECTION_COMPLETE:
        rv = DoInitConnectionComplete(rv);
        break;
      case STATE_WAITING_USER_ACTION:
        rv = DoWaitingUserAction(rv);
        break;
      case STATE_RESTART_TUNNEL_AUTH:
        DCHECK_EQ(OK, rv);
        rv = DoRestartTunnelAuth();
        break;
      case STATE_RESTART_TUNNEL_AUTH_COMPLETE:
        rv = DoRestartTunnelAuthComplete(rv);
        break;
      case STATE_CREATE_STREAM:
        DCHECK_EQ(OK, rv);
        rv = DoCreateStream();
        break;
      case STATE_CREATE_STREAM_COMPLETE:
        rv = DoCreateStreamComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
        rv = ERR_FAILED;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
  return rv;
}

int HttpStreamFactoryImpl::Job::StartInternal() {
  CHECK_EQ(STATE_NONE, next_state_);
  next_state_ = STATE_START;
  int rv = RunLoop(OK);
  DCHECK_EQ(ERR_IO_PENDING, rv);
  return rv;
}

int HttpStreamFactoryImpl::Job::DoStart() {
  const NetLogWithSource* net_log = delegate_->GetNetLog(this);

  if (net_log) {
    net_log_.BeginEvent(
        NetLogEventType::HTTP_STREAM_JOB,
        base::Bind(&NetLogHttpStreamJobCallback, net_log->source(),
                   &request_info_.url, &origin_url_, &alternative_service_,
                   priority_));
    net_log->AddEvent(NetLogEventType::HTTP_STREAM_REQUEST_STARTED_JOB,
                      net_log_.source().ToEventParametersCallback());
  }

  // Don't connect to restricted ports.
  if (!IsPortAllowedForScheme(destination_.port(),
                              request_info_.url.scheme())) {
    return ERR_UNSAFE_PORT;
  }

  next_state_ = STATE_RESOLVE_PROXY;
  return OK;
}

int HttpStreamFactoryImpl::Job::DoResolveProxy() {
  DCHECK(!pac_request_);
  DCHECK(session_);

  next_state_ = STATE_RESOLVE_PROXY_COMPLETE;

  if (request_info_.load_flags & LOAD_BYPASS_PROXY) {
    proxy_info_.UseDirect();
    return OK;
  }

  // If an alternative proxy server was provided, use that.
  if (alternative_proxy_server_.is_valid()) {
    proxy_info_.UseProxyServer(alternative_proxy_server_);
    return OK;
  }

  return session_->proxy_service()->ResolveProxy(
      origin_url_, request_info_.method, &proxy_info_, io_callback_,
      &pac_request_, session_->params().proxy_delegate, net_log_);
}

int HttpStreamFactoryImpl::Job::DoResolveProxyComplete(int result) {
  pac_request_ = NULL;

  if (result == OK) {
    // Remove unsupported proxies from the list.
    int supported_proxies =
        ProxyServer::SCHEME_DIRECT | ProxyServer::SCHEME_HTTP |
        ProxyServer::SCHEME_HTTPS | ProxyServer::SCHEME_SOCKS4 |
        ProxyServer::SCHEME_SOCKS5;

    if (session_->IsQuicEnabled())
      supported_proxies |= ProxyServer::SCHEME_QUIC;

    proxy_info_.RemoveProxiesWithoutScheme(supported_proxies);

    if (proxy_info_.is_empty()) {
      // No proxies/direct to choose from. This happens when we don't support
      // any of the proxies in the returned list.
      result = ERR_NO_SUPPORTED_PROXIES;
    } else if (using_quic_ &&
               (!proxy_info_.is_quic() && !proxy_info_.is_direct())) {
      // QUIC can not be spoken to non-QUIC proxies.  This error should not be
      // user visible, because the non-alternative Job should be resumed.
      result = ERR_NO_SUPPORTED_PROXIES;
    }
  }

  if (result != OK) {
    return result;
  }

  next_state_ = STATE_WAIT;

  delegate_->OnResolveProxyComplete(this, request_info_, priority_,
                                    server_ssl_config_, proxy_ssl_config_,
                                    stream_type_);

  return OK;
}

bool HttpStreamFactoryImpl::Job::ShouldForceQuic() const {
  return session_->IsQuicEnabled() &&
         (base::ContainsKey(session_->params().origins_to_force_quic_on,
                            HostPortPair()) ||
          base::ContainsKey(session_->params().origins_to_force_quic_on,
                            destination_)) &&
         proxy_info_.is_direct() && origin_url_.SchemeIs(url::kHttpsScheme);
}

int HttpStreamFactoryImpl::Job::DoWait() {
  next_state_ = STATE_WAIT_COMPLETE;
  if (delegate_->ShouldWait(this))
    return ERR_IO_PENDING;

  return OK;
}

int HttpStreamFactoryImpl::Job::DoWaitComplete(int result) {
  DCHECK_EQ(OK, result);
  next_state_ = STATE_INIT_CONNECTION;
  return OK;
}

int HttpStreamFactoryImpl::Job::DoInitConnection() {
  int result = DoInitConnectionImpl();
  if (result != ERR_SPDY_SESSION_ALREADY_EXISTS)
    delegate_->OnConnectionInitialized(this, result);

  return result;
}

int HttpStreamFactoryImpl::Job::DoInitConnectionImpl() {
  // TODO(pkasting): Remove ScopedTracker below once crbug.com/462812 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "462812 HttpStreamFactoryImpl::Job::DoInitConnection"));
  DCHECK(!connection_->is_initialized());
  DCHECK(proxy_info_.proxy_server().is_valid());
  next_state_ = STATE_INIT_CONNECTION_COMPLETE;

  if (delegate_->OnInitConnection(proxy_info_)) {
    // Return since the connection initialization can be skipped.
    return OK;
  }

  using_ssl_ = origin_url_.SchemeIs(url::kHttpsScheme) ||
               origin_url_.SchemeIs(url::kWssScheme);
  using_spdy_ = false;

  if (ShouldForceQuic())
    using_quic_ = true;

  DCHECK(!using_quic_ || session_->IsQuicEnabled());

  if (proxy_info_.is_quic()) {
    using_quic_ = true;
    DCHECK(session_->IsQuicEnabled());
  }

  if (proxy_info_.is_https() || proxy_info_.is_quic()) {
    InitSSLConfig(&proxy_ssl_config_, /*is_proxy=*/true);
    // Disable revocation checking for HTTPS proxies since the revocation
    // requests are probably going to need to go through the proxy too.
    proxy_ssl_config_.rev_checking_enabled = false;
  }
  if (using_ssl_) {
    InitSSLConfig(&server_ssl_config_, /*is_proxy=*/false);
  }

  if (using_quic_) {
    if (proxy_info_.is_quic() &&
        !request_info_.url.SchemeIs(url::kHttpScheme)) {
      NOTREACHED();
      // TODO(rch): support QUIC proxies for HTTPS urls.
      return ERR_NOT_IMPLEMENTED;
    }
    HostPortPair destination;
    SSLConfig* ssl_config;
    GURL url(request_info_.url);
    if (proxy_info_.is_quic()) {
      // A proxy's certificate is expected to be valid for the proxy hostname.
      destination = proxy_info_.proxy_server().host_port_pair();
      ssl_config = &proxy_ssl_config_;
      GURL::Replacements replacements;
      replacements.SetSchemeStr(url::kHttpsScheme);
      replacements.SetHostStr(destination.host());
      const std::string new_port = base::UintToString(destination.port());
      replacements.SetPortStr(new_port);
      replacements.ClearUsername();
      replacements.ClearPassword();
      replacements.ClearPath();
      replacements.ClearQuery();
      replacements.ClearRef();
      url = url.ReplaceComponents(replacements);

      if (session_->quic_stream_factory()->IsQuicDisabled())
        return ERR_QUIC_PROTOCOL_ERROR;
    } else {
      DCHECK(using_ssl_);
      // The certificate of a QUIC alternative server is expected to be valid
      // for the origin of the request (in addition to being valid for the
      // server itself).
      destination = destination_;
      ssl_config = &server_ssl_config_;
    }
    int rv =
        quic_request_.Request(destination, request_info_.privacy_mode,
                              ssl_config->GetCertVerifyFlags(), url,
                              request_info_.method, net_log_, io_callback_);
    if (rv == OK) {
      using_existing_quic_session_ = true;
    } else {
      // There's no available QUIC session. Inform the delegate how long to
      // delay the main job.
      if (rv == ERR_IO_PENDING) {
        delegate_->MaybeSetWaitTimeForMainJob(
            quic_request_.GetTimeDelayForWaitingJob());
      }
    }
    return rv;
  }

  SpdySessionKey spdy_session_key = GetSpdySessionKey();

  // Check first if we have a spdy session for this group.  If so, then go
  // straight to using that.
  if (CanUseExistingSpdySession()) {
    base::WeakPtr<SpdySession> spdy_session =
        session_->spdy_session_pool()->FindAvailableSession(
            spdy_session_key, origin_url_, net_log_);
    if (spdy_session) {
      // If we're preconnecting, but we already have a SpdySession, we don't
      // actually need to preconnect any sockets, so we're done.
      if (job_type_ == PRECONNECT)
        return OK;
      using_spdy_ = true;
      next_state_ = STATE_CREATE_STREAM;
      existing_spdy_session_ = spdy_session;
      return OK;
    }
  }
  if (using_ssl_) {
    // Ask |delegate_delegate_| to update the spdy session key for the request
    // that launched this job.
    delegate_->SetSpdySessionKey(this, spdy_session_key);
  }

  if (proxy_info_.is_http() || proxy_info_.is_https())
    establishing_tunnel_ = using_ssl_;

  const bool expect_spdy = IsSpdyAlternative();

  HttpServerProperties* http_server_properties =
      session_->http_server_properties();
  if (http_server_properties) {
    http_server_properties->MaybeForceHTTP11(destination_, &server_ssl_config_);
    if (proxy_info_.is_http() || proxy_info_.is_https()) {
      http_server_properties->MaybeForceHTTP11(
          proxy_info_.proxy_server().host_port_pair(), &proxy_ssl_config_);
    }
  }

  if (job_type_ == PRECONNECT) {
    DCHECK(!delegate_->for_websockets());
    return PreconnectSocketsForHttpRequest(
        GetSocketGroup(), destination_, request_info_.extra_headers,
        request_info_.load_flags, priority_, session_, proxy_info_, expect_spdy,
        server_ssl_config_, proxy_ssl_config_, request_info_.privacy_mode,
        net_log_, num_streams_);
  }

  // If we can't use a SPDY session, don't bother checking for one after
  // the hostname is resolved.
  OnHostResolutionCallback resolution_callback =
      CanUseExistingSpdySession()
          ? base::Bind(&Job::OnHostResolution, session_->spdy_session_pool(),
                       spdy_session_key, origin_url_)
          : OnHostResolutionCallback();
  if (delegate_->for_websockets()) {
    // TODO(ricea): Re-enable NPN when WebSockets over SPDY is supported.
    SSLConfig websocket_server_ssl_config = server_ssl_config_;
    websocket_server_ssl_config.alpn_protos.clear();
    return InitSocketHandleForWebSocketRequest(
        GetSocketGroup(), destination_, request_info_.extra_headers,
        request_info_.load_flags, priority_, session_, proxy_info_, expect_spdy,
        websocket_server_ssl_config, proxy_ssl_config_,
        request_info_.privacy_mode, net_log_, connection_.get(),
        resolution_callback, io_callback_);
  }

  return InitSocketHandleForHttpRequest(
      GetSocketGroup(), destination_, request_info_.extra_headers,
      request_info_.load_flags, priority_, session_, proxy_info_, expect_spdy,
      server_ssl_config_, proxy_ssl_config_, request_info_.privacy_mode,
      net_log_, connection_.get(), resolution_callback, io_callback_);
}

int HttpStreamFactoryImpl::Job::DoInitConnectionComplete(int result) {
  if (job_type_ == PRECONNECT) {
    if (using_quic_)
      return result;
    DCHECK_EQ(OK, result);
    return OK;
  }

  if (result == ERR_SPDY_SESSION_ALREADY_EXISTS) {
    // We found a SPDY connection after resolving the host. This is
    // probably an IP pooled connection.
    SpdySessionKey spdy_session_key = GetSpdySessionKey();
    existing_spdy_session_ =
        session_->spdy_session_pool()->FindAvailableSession(
            spdy_session_key, origin_url_, net_log_);
    if (existing_spdy_session_) {
      using_spdy_ = true;
      next_state_ = STATE_CREATE_STREAM;
    } else {
      // It is possible that the spdy session no longer exists.
      ReturnToStateInitConnection(true /* close connection */);
    }
    return OK;
  }

  if (proxy_info_.is_quic()) {
    DCHECK(using_quic_);
    // Mark QUIC proxy as bad if QUIC got disabled.
    // Underlying QUIC layer would have closed the connection.
    if (session_->quic_stream_factory()->IsQuicDisabled()) {
      using_quic_ = false;
      return ReconsiderProxyAfterError(ERR_QUIC_PROTOCOL_ERROR);
    }
  }

  // |result| may be the result of any of the stacked pools. The following
  // logic is used when determining how to interpret an error.
  // If |result| < 0:
  //   and connection_->socket() != NULL, then the SSL handshake ran and it
  //     is a potentially recoverable error.
  //   and connection_->socket == NULL and connection_->is_ssl_error() is true,
  //     then the SSL handshake ran with an unrecoverable error.
  //   otherwise, the error came from one of the other pools.
  bool ssl_started = using_ssl_ && (result == OK || connection_->socket() ||
                                    connection_->is_ssl_error());

  if (ssl_started && (result == OK || IsCertificateError(result))) {
    if (using_quic_ && result == OK) {
      was_alpn_negotiated_ = true;
      negotiated_protocol_ = kProtoQUIC;
    } else {
      SSLClientSocket* ssl_socket =
          static_cast<SSLClientSocket*>(connection_->socket());
      if (ssl_socket->WasAlpnNegotiated()) {
        was_alpn_negotiated_ = true;
        negotiated_protocol_ = ssl_socket->GetNegotiatedProtocol();
        net_log_.AddEvent(
            NetLogEventType::HTTP_STREAM_REQUEST_PROTO,
            base::Bind(&NetLogHttpStreamProtoCallback, negotiated_protocol_));
        if (negotiated_protocol_ == kProtoHTTP2)
          using_spdy_ = true;
      }
    }
  } else if (proxy_info_.is_https() && connection_->socket() &&
        result == OK) {
    ProxyClientSocket* proxy_socket =
      static_cast<ProxyClientSocket*>(connection_->socket());
    // http://crbug.com/642354
    if (!proxy_socket->IsConnected())
      return ERR_CONNECTION_CLOSED;
    if (proxy_socket->IsUsingSpdy()) {
      was_alpn_negotiated_ = true;
      negotiated_protocol_ = proxy_socket->GetProxyNegotiatedProtocol();
      using_spdy_ = true;
    }
  }

  if (result == ERR_PROXY_AUTH_REQUESTED ||
      result == ERR_HTTPS_PROXY_TUNNEL_RESPONSE) {
    DCHECK(!ssl_started);
    // Other state (i.e. |using_ssl_|) suggests that |connection_| will have an
    // SSL socket, but there was an error before that could happen.  This
    // puts the in progress HttpProxy socket into |connection_| in order to
    // complete the auth (or read the response body).  The tunnel restart code
    // is careful to remove it before returning control to the rest of this
    // class.
    connection_.reset(connection_->release_pending_http_proxy_connection());
    return result;
  }

  if (proxy_info_.is_quic() && using_quic_ && result < 0) {
    using_quic_ = false;
    return ReconsiderProxyAfterError(result);
  }

  if (IsSpdyAlternative() && !using_spdy_)
    return ERR_ALPN_NEGOTIATION_FAILED;

  if (!ssl_started && result < 0 &&
      (IsSpdyAlternative() || IsQuicAlternative()))
    return result;

  if (using_quic_) {
    if (result < 0)
      return result;

    if (stream_type_ == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
      bidirectional_stream_impl_ =
          quic_request_.CreateBidirectionalStreamImpl();
      if (!bidirectional_stream_impl_) {
        // Quic session is closed before stream can be created.
        return ERR_CONNECTION_CLOSED;
      }
    } else {
      stream_ = quic_request_.CreateStream();
      if (!stream_) {
        // Quic session is closed before stream can be created.
        return ERR_CONNECTION_CLOSED;
      }
    }
    next_state_ = STATE_NONE;
    return OK;
  }

  if (result < 0 && !ssl_started)
    return ReconsiderProxyAfterError(result);
  establishing_tunnel_ = false;

  // Handle SSL errors below.
  if (using_ssl_) {
    DCHECK(ssl_started);
    if (IsCertificateError(result)) {
      result = HandleCertificateError(result);
      if (result == OK && !connection_->socket()->IsConnectedAndIdle()) {
        ReturnToStateInitConnection(true /* close connection */);
        return result;
      }
    }
    if (result < 0)
      return result;
  }

  next_state_ = STATE_CREATE_STREAM;
  return OK;
}

int HttpStreamFactoryImpl::Job::DoWaitingUserAction(int result) {
  // This state indicates that the stream request is in a partially
  // completed state, and we've called back to the delegate for more
  // information.

  // We're always waiting here for the delegate to call us back.
  return ERR_IO_PENDING;
}

int HttpStreamFactoryImpl::Job::SetSpdyHttpStreamOrBidirectionalStreamImpl(
    base::WeakPtr<SpdySession> session,
    bool direct) {
  // TODO(ricea): Restore the code for WebSockets over SPDY once it's
  // implemented.
  if (delegate_->for_websockets())
    return ERR_NOT_IMPLEMENTED;
  if (stream_type_ == HttpStreamRequest::BIDIRECTIONAL_STREAM) {
    bidirectional_stream_impl_.reset(new BidirectionalStreamSpdyImpl(session));
    return OK;
  }

  // TODO(willchan): Delete this code, because eventually, the
  // HttpStreamFactoryImpl will be creating all the SpdyHttpStreams, since it
  // will know when SpdySessions become available.

  bool use_relative_url =
      direct || request_info_.url.SchemeIs(url::kHttpsScheme);
  stream_.reset(new SpdyHttpStream(session, use_relative_url));
  return OK;
}

int HttpStreamFactoryImpl::Job::DoCreateStream() {
  // TODO(pkasting): Remove ScopedTracker below once crbug.com/462811 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "462811 HttpStreamFactoryImpl::Job::DoCreateStream"));
  DCHECK(connection_->socket() || existing_spdy_session_.get() || using_quic_);
  DCHECK(!IsQuicAlternative());

  next_state_ = STATE_CREATE_STREAM_COMPLETE;

  if (using_ssl_ && connection_->socket()) {
    SSLClientSocket* ssl_socket =
        static_cast<SSLClientSocket*>(connection_->socket());
    RecordChannelIDKeyMatch(ssl_socket, session_->params().channel_id_service,
                            destination_.HostForURL());
  }

  // We only set the socket motivation if we're the first to use
  // this socket.  Is there a race for two SPDY requests?  We really
  // need to plumb this through to the connect level.
  if (connection_->socket() && !connection_->is_reused())
    SetSocketMotivation();

  if (!using_spdy_) {
    DCHECK(!IsSpdyAlternative());
    // We may get ftp scheme when fetching ftp resources through proxy.
    bool using_proxy = (proxy_info_.is_http() || proxy_info_.is_https()) &&
                       (request_info_.url.SchemeIs(url::kHttpScheme) ||
                        request_info_.url.SchemeIs(url::kFtpScheme));
    if (delegate_->for_websockets()) {
      DCHECK_NE(job_type_, PRECONNECT);
      DCHECK(delegate_->websocket_handshake_stream_create_helper());
      websocket_stream_.reset(
          delegate_->websocket_handshake_stream_create_helper()
              ->CreateBasicStream(std::move(connection_), using_proxy));
    } else {
      stream_.reset(new HttpBasicStream(
          std::move(connection_), using_proxy,
          session_->params().http_09_on_non_default_ports_enabled));
    }
    return OK;
  }

  CHECK(!stream_.get());

  bool direct = !IsHttpsProxyAndHttpUrl();
  if (existing_spdy_session_.get()) {
    // We picked up an existing session, so we don't need our socket.
    if (connection_->socket())
      connection_->socket()->Disconnect();
    connection_->Reset();

    int set_result = SetSpdyHttpStreamOrBidirectionalStreamImpl(
        existing_spdy_session_, direct);
    existing_spdy_session_.reset();
    return set_result;
  }

  SpdySessionKey spdy_session_key = GetSpdySessionKey();
  base::WeakPtr<SpdySession> spdy_session =
      session_->spdy_session_pool()->FindAvailableSession(
          spdy_session_key, origin_url_, net_log_);
  if (spdy_session) {
    return SetSpdyHttpStreamOrBidirectionalStreamImpl(spdy_session, direct);
  }

  spdy_session =
      session_->spdy_session_pool()->CreateAvailableSessionFromSocket(
          spdy_session_key, std::move(connection_), net_log_, using_ssl_);

  if (!spdy_session->HasAcceptableTransportSecurity()) {
    spdy_session->CloseSessionOnError(
        ERR_SPDY_INADEQUATE_TRANSPORT_SECURITY, "");
    return ERR_SPDY_INADEQUATE_TRANSPORT_SECURITY;
  }

  SSLInfo ssl_info;
  if (spdy_session->GetSSLInfo(&ssl_info)) {
    UMA_HISTOGRAM_SPARSE_SLOWLY(
        "Net.Http2SSLCipherSuite",
        SSLConnectionStatusToCipherSuite(ssl_info.connection_status));
  }

  new_spdy_session_ = spdy_session;
  spdy_session_direct_ = direct;
  const HostPortPair host_port_pair = spdy_session_key.host_port_pair();
  bool is_https = ssl_info.is_valid();
  url::SchemeHostPort scheme_host_port(
      is_https ? url::kHttpsScheme : url::kHttpScheme, host_port_pair.host(),
      host_port_pair.port());

  HttpServerProperties* http_server_properties =
      session_->http_server_properties();
  if (http_server_properties)
    http_server_properties->SetSupportsSpdy(scheme_host_port, true);

  // Create a SpdyHttpStream or a BidirectionalStreamImpl attached to the
  // session; OnNewSpdySessionReadyCallback is not called until an event loop
  // iteration later, so if the SpdySession is closed between then, allow
  // reuse state from the underlying socket, sampled by SpdyHttpStream,
  // bubble up to the request.
  return SetSpdyHttpStreamOrBidirectionalStreamImpl(new_spdy_session_,
                                                    spdy_session_direct_);
}

int HttpStreamFactoryImpl::Job::DoCreateStreamComplete(int result) {
  if (result < 0)
    return result;

  session_->proxy_service()->ReportSuccess(proxy_info_,
                                           session_->params().proxy_delegate);
  next_state_ = STATE_NONE;
  return OK;
}

int HttpStreamFactoryImpl::Job::DoRestartTunnelAuth() {
  next_state_ = STATE_RESTART_TUNNEL_AUTH_COMPLETE;
  ProxyClientSocket* proxy_socket =
      static_cast<ProxyClientSocket*>(connection_->socket());
  return proxy_socket->RestartWithAuth(io_callback_);
}

int HttpStreamFactoryImpl::Job::DoRestartTunnelAuthComplete(int result) {
  if (result == ERR_PROXY_AUTH_REQUESTED)
    return result;

  if (result == OK) {
    // Now that we've got the HttpProxyClientSocket connected.  We have
    // to release it as an idle socket into the pool and start the connection
    // process from the beginning.  Trying to pass it in with the
    // SSLSocketParams might cause a deadlock since params are dispatched
    // interchangeably.  This request won't necessarily get this http proxy
    // socket, but there will be forward progress.
    establishing_tunnel_ = false;
    ReturnToStateInitConnection(false /* do not close connection */);
    return OK;
  }

  return ReconsiderProxyAfterError(result);
}

void HttpStreamFactoryImpl::Job::ReturnToStateInitConnection(
    bool close_connection) {
  if (close_connection && connection_->socket())
    connection_->socket()->Disconnect();
  connection_->Reset();

  delegate_->RemoveRequestFromSpdySessionRequestMapForJob(this);

  next_state_ = STATE_INIT_CONNECTION;
}

void HttpStreamFactoryImpl::Job::SetSocketMotivation() {
  if (request_info_.motivation == HttpRequestInfo::PRECONNECT_MOTIVATED)
    connection_->socket()->SetSubresourceSpeculation();
  else if (request_info_.motivation == HttpRequestInfo::OMNIBOX_MOTIVATED)
    connection_->socket()->SetOmniboxSpeculation();
  // TODO(mbelshe): Add other motivations (like EARLY_LOAD_MOTIVATED).
}

bool HttpStreamFactoryImpl::Job::IsHttpsProxyAndHttpUrl() const {
  if (!proxy_info_.is_https())
    return false;
  DCHECK(!IsSpdyAlternative());
  if (IsQuicAlternative()) {
    // We currently only support Alternate-Protocol where the original scheme
    // is http.
    // TODO(bnc): This comment is probably incorrect.
    DCHECK(origin_url_.SchemeIs(url::kHttpScheme));
    return origin_url_.SchemeIs(url::kHttpScheme);
  }
  return request_info_.url.SchemeIs(url::kHttpScheme);
}

bool HttpStreamFactoryImpl::Job::IsSpdyAlternative() const {
  return alternative_service_.protocol == kProtoHTTP2;
}

bool HttpStreamFactoryImpl::Job::IsQuicAlternative() const {
  return alternative_service_.protocol == kProtoQUIC;
}

void HttpStreamFactoryImpl::Job::InitSSLConfig(SSLConfig* ssl_config,
                                               bool is_proxy) const {
  if (!is_proxy) {
    // Prior to HTTP/2 and SPDY, some servers use TLS renegotiation to request
    // TLS client authentication after the HTTP request was sent. Allow
    // renegotiation for only those connections.
    //
    // Note that this does NOT implement the provision in
    // https://http2.github.io/http2-spec/#rfc.section.9.2.1 which allows the
    // server to request a renegotiation immediately before sending the
    // connection preface as waiting for the preface would cost the round trip
    // that False Start otherwise saves.
    ssl_config->renego_allowed_default = true;
    ssl_config->renego_allowed_for_protos.push_back(kProtoHTTP11);
  }

  if (proxy_info_.is_https() && ssl_config->send_client_cert) {
    // When connecting through an HTTPS proxy, disable TLS False Start so
    // that client authentication errors can be distinguished between those
    // originating from the proxy server (ERR_PROXY_CONNECTION_FAILED) and
    // those originating from the endpoint (ERR_SSL_PROTOCOL_ERROR /
    // ERR_BAD_SSL_CLIENT_AUTH_CERT).
    //
    // This assumes the proxy will only request certificates on the initial
    // handshake; renegotiation on the proxy connection is unsupported.
    ssl_config->false_start_enabled = false;
  }

  if (request_info_.load_flags & LOAD_VERIFY_EV_CERT)
    ssl_config->verify_ev_cert = true;

  // Disable Channel ID if privacy mode is enabled.
  if (request_info_.privacy_mode == PRIVACY_MODE_ENABLED)
    ssl_config->channel_id_enabled = false;
}


int HttpStreamFactoryImpl::Job::ReconsiderProxyAfterError(int error) {
  DCHECK(!pac_request_);
  DCHECK(session_);

  // A failure to resolve the hostname or any error related to establishing a
  // TCP connection could be grounds for trying a new proxy configuration.
  //
  // Why do this when a hostname cannot be resolved?  Some URLs only make sense
  // to proxy servers.  The hostname in those URLs might fail to resolve if we
  // are still using a non-proxy config.  We need to check if a proxy config
  // now exists that corresponds to a proxy server that could load the URL.
  //
  switch (error) {
    case ERR_PROXY_CONNECTION_FAILED:
    case ERR_NAME_NOT_RESOLVED:
    case ERR_INTERNET_DISCONNECTED:
    case ERR_ADDRESS_UNREACHABLE:
    case ERR_CONNECTION_CLOSED:
    case ERR_CONNECTION_TIMED_OUT:
    case ERR_CONNECTION_RESET:
    case ERR_CONNECTION_REFUSED:
    case ERR_CONNECTION_ABORTED:
    case ERR_TIMED_OUT:
    case ERR_TUNNEL_CONNECTION_FAILED:
    case ERR_SOCKS_CONNECTION_FAILED:
    // ERR_PROXY_CERTIFICATE_INVALID can happen in the case of trying to talk to
    // a proxy using SSL, and ending up talking to a captive portal that
    // supports SSL instead.
    case ERR_PROXY_CERTIFICATE_INVALID:
    case ERR_QUIC_PROTOCOL_ERROR:
    case ERR_QUIC_HANDSHAKE_FAILED:
    case ERR_MSG_TOO_BIG:
    // ERR_SSL_PROTOCOL_ERROR can happen when trying to talk SSL to a non-SSL
    // server (like a captive portal).
    case ERR_SSL_PROTOCOL_ERROR:
      break;
    case ERR_SOCKS_CONNECTION_HOST_UNREACHABLE:
      // Remap the SOCKS-specific "host unreachable" error to a more
      // generic error code (this way consumers like the link doctor
      // know to substitute their error page).
      //
      // Note that if the host resolving was done by the SOCKS5 proxy, we can't
      // differentiate between a proxy-side "host not found" versus a proxy-side
      // "address unreachable" error, and will report both of these failures as
      // ERR_ADDRESS_UNREACHABLE.
      return ERR_ADDRESS_UNREACHABLE;
    default:
      return error;
  }

  // Do not bypass non-QUIC proxy on ERR_MSG_TOO_BIG.
  if (!proxy_info_.is_quic() && error == ERR_MSG_TOO_BIG)
    return error;

  if (request_info_.load_flags & LOAD_BYPASS_PROXY)
    return error;

  // Alternative proxy server job should not use fallback proxies, and instead
  // return. This would resume the main job (if possible) which may try the
  // fallback proxies.
  if (alternative_proxy_server_.is_valid()) {
    DCHECK_EQ(STATE_NONE, next_state_);
    return error;
  }

  if (proxy_info_.is_https() && proxy_ssl_config_.send_client_cert) {
    session_->ssl_client_auth_cache()->Remove(
        proxy_info_.proxy_server().host_port_pair());
  }

  int rv = session_->proxy_service()->ReconsiderProxyAfterError(
      request_info_.url, request_info_.method, error, &proxy_info_,
      io_callback_, &pac_request_, session_->params().proxy_delegate, net_log_);
  if (rv == OK || rv == ERR_IO_PENDING) {
    // If the error was during connection setup, there is no socket to
    // disconnect.
    if (connection_->socket())
      connection_->socket()->Disconnect();
    connection_->Reset();
    delegate_->RemoveRequestFromSpdySessionRequestMapForJob(this);
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

int HttpStreamFactoryImpl::Job::HandleCertificateError(int error) {
  DCHECK(using_ssl_);
  DCHECK(IsCertificateError(error));

  SSLClientSocket* ssl_socket =
      static_cast<SSLClientSocket*>(connection_->socket());
  ssl_socket->GetSSLInfo(&ssl_info_);

  if (!ssl_info_.cert) {
    // If the server's certificate could not be parsed, there is no way
    // to gracefully recover this, so just pass the error up.
    return error;
  }

  // Add the bad certificate to the set of allowed certificates in the
  // SSL config object. This data structure will be consulted after calling
  // RestartIgnoringLastError(). And the user will be asked interactively
  // before RestartIgnoringLastError() is ever called.
  server_ssl_config_.allowed_bad_certs.emplace_back(ssl_info_.cert,
                                                    ssl_info_.cert_status);

  int load_flags = request_info_.load_flags;
  if (session_->params().ignore_certificate_errors)
    load_flags |= LOAD_IGNORE_ALL_CERT_ERRORS;
  if (ssl_socket->IgnoreCertError(error, load_flags))
    return OK;
  return error;
}

ClientSocketPoolManager::SocketGroupType
HttpStreamFactoryImpl::Job::GetSocketGroup() const {
  std::string scheme = origin_url_.scheme();
  if (scheme == url::kHttpsScheme || scheme == url::kWssScheme)
    return ClientSocketPoolManager::SSL_GROUP;

  if (scheme == url::kFtpScheme)
    return ClientSocketPoolManager::FTP_GROUP;

  return ClientSocketPoolManager::NORMAL_GROUP;
}

// If the connection succeeds, failed connection attempts leading up to the
// success will be returned via the successfully connected socket. If the
// connection fails, failed connection attempts will be returned via the
// ClientSocketHandle. Check whether a socket was returned and copy the
// connection attempts from the proper place.
void HttpStreamFactoryImpl::Job::
    MaybeCopyConnectionAttemptsFromSocketOrHandle() {
  if (!connection_)
    return;

  ConnectionAttempts socket_attempts = connection_->connection_attempts();
  if (connection_->socket()) {
    connection_->socket()->GetConnectionAttempts(&socket_attempts);
  }

  delegate_->AddConnectionAttemptsToRequest(this, socket_attempts);
}

}  // namespace net
