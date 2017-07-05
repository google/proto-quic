// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_proxy_client_socket_wrapper.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/profiler/scoped_tracker.h"
#include "base/values.h"
#include "net/base/proxy_delegate.h"
#include "net/http/http_proxy_client_socket.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/socket/client_socket_handle.h"
#include "net/spdy/chromium/spdy_proxy_client_socket.h"
#include "net/spdy/chromium/spdy_session.h"
#include "net/spdy/chromium/spdy_session_pool.h"
#include "net/spdy/chromium/spdy_stream.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "url/gurl.h"

namespace net {

HttpProxyClientSocketWrapper::HttpProxyClientSocketWrapper(
    const std::string& group_name,
    RequestPriority priority,
    ClientSocketPool::RespectLimits respect_limits,
    base::TimeDelta connect_timeout_duration,
    base::TimeDelta proxy_negotiation_timeout_duration,
    TransportClientSocketPool* transport_pool,
    SSLClientSocketPool* ssl_pool,
    const scoped_refptr<TransportSocketParams>& transport_params,
    const scoped_refptr<SSLSocketParams>& ssl_params,
    const std::string& user_agent,
    const HostPortPair& endpoint,
    HttpAuthCache* http_auth_cache,
    HttpAuthHandlerFactory* http_auth_handler_factory,
    SpdySessionPool* spdy_session_pool,
    bool tunnel,
    ProxyDelegate* proxy_delegate,
    const NetLogWithSource& net_log)
    : next_state_(STATE_NONE),
      group_name_(group_name),
      priority_(priority),
      respect_limits_(respect_limits),
      connect_timeout_duration_(connect_timeout_duration),
      proxy_negotiation_timeout_duration_(proxy_negotiation_timeout_duration),
      transport_pool_(transport_pool),
      ssl_pool_(ssl_pool),
      transport_params_(transport_params),
      ssl_params_(ssl_params),
      user_agent_(user_agent),
      endpoint_(endpoint),
      spdy_session_pool_(spdy_session_pool),
      has_restarted_(false),
      tunnel_(tunnel),
      proxy_delegate_(proxy_delegate),
      using_spdy_(false),
      http_auth_controller_(
          tunnel ? new HttpAuthController(
                       HttpAuth::AUTH_PROXY,
                       GURL((ssl_params_.get() ? "https://" : "http://") +
                            GetDestination().host_port_pair().ToString()),
                       http_auth_cache,
                       http_auth_handler_factory)
                 : nullptr),
      net_log_(NetLogWithSource::Make(
          net_log.net_log(),
          NetLogSourceType::PROXY_CLIENT_SOCKET_WRAPPER)) {
  net_log_.BeginEvent(NetLogEventType::SOCKET_ALIVE,
                      net_log.source().ToEventParametersCallback());
  DCHECK(transport_params || ssl_params);
  DCHECK(!transport_params || !ssl_params);
}

HttpProxyClientSocketWrapper::~HttpProxyClientSocketWrapper() {
  // Make sure no sockets are returned to the lower level socket pools.
  Disconnect();

  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
}

LoadState HttpProxyClientSocketWrapper::GetConnectLoadState() const {
  switch (next_state_) {
    case STATE_BEGIN_CONNECT:
    case STATE_TCP_CONNECT:
    case STATE_TCP_CONNECT_COMPLETE:
    case STATE_SSL_CONNECT:
    case STATE_SSL_CONNECT_COMPLETE:
      return transport_socket_handle_->GetLoadState();
    case STATE_HTTP_PROXY_CONNECT:
    case STATE_HTTP_PROXY_CONNECT_COMPLETE:
    case STATE_SPDY_PROXY_CREATE_STREAM:
    case STATE_SPDY_PROXY_CREATE_STREAM_COMPLETE:
    case STATE_SPDY_PROXY_CONNECT_COMPLETE:
    case STATE_RESTART_WITH_AUTH:
    case STATE_RESTART_WITH_AUTH_COMPLETE:
      return LOAD_STATE_ESTABLISHING_PROXY_TUNNEL;
    case STATE_NONE:
      // May be possible for this method to be called after an error, shouldn't
      // be called after a successful connect.
      break;
  }
  return LOAD_STATE_IDLE;
}

std::unique_ptr<HttpResponseInfo>
HttpProxyClientSocketWrapper::GetAdditionalErrorState() {
  return std::move(error_response_info_);
}

const HttpResponseInfo* HttpProxyClientSocketWrapper::GetConnectResponseInfo()
    const {
  if (transport_socket_)
    return transport_socket_->GetConnectResponseInfo();
  return nullptr;
}

std::unique_ptr<HttpStream>
HttpProxyClientSocketWrapper::CreateConnectResponseStream() {
  if (transport_socket_)
    return transport_socket_->CreateConnectResponseStream();
  return nullptr;
}

int HttpProxyClientSocketWrapper::RestartWithAuth(
    const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  DCHECK(connect_callback_.is_null());
  DCHECK(transport_socket_);
  DCHECK_EQ(STATE_NONE, next_state_);

  connect_callback_ = callback;
  next_state_ = STATE_RESTART_WITH_AUTH;
  return DoLoop(OK);
}

const scoped_refptr<HttpAuthController>&
HttpProxyClientSocketWrapper::GetAuthController() const {
  return http_auth_controller_;
}

bool HttpProxyClientSocketWrapper::IsUsingSpdy() const {
  if (transport_socket_)
    return transport_socket_->IsUsingSpdy();
  return false;
}

NextProto HttpProxyClientSocketWrapper::GetProxyNegotiatedProtocol() const {
  if (transport_socket_)
    return transport_socket_->GetProxyNegotiatedProtocol();
  return kProtoUnknown;
}

int HttpProxyClientSocketWrapper::Connect(const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  DCHECK(connect_callback_.is_null());

  // If connecting or previously connected and not disconnected, return OK, to
  // match TCPClientSocket's behavior.
  if (next_state_ != STATE_NONE || transport_socket_)
    return OK;

  next_state_ = STATE_BEGIN_CONNECT;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    connect_callback_ = callback;
  } else {
    connect_timer_.Stop();
    NotifyProxyDelegateOfCompletion(rv);
  }

  return rv;
}

void HttpProxyClientSocketWrapper::Disconnect() {
  connect_callback_.Reset();
  connect_timer_.Stop();
  next_state_ = STATE_NONE;
  spdy_stream_request_.CancelRequest();
  if (transport_socket_handle_) {
    if (transport_socket_handle_->socket())
      transport_socket_handle_->socket()->Disconnect();
    transport_socket_handle_->Reset();
    transport_socket_handle_.reset();
  }

  if (transport_socket_)
    transport_socket_->Disconnect();
}

bool HttpProxyClientSocketWrapper::IsConnected() const {
  if (transport_socket_)
    return transport_socket_->IsConnected();
  // Don't return true if still connecting.  Shouldn't really matter, either
  // way.
  return false;
}

bool HttpProxyClientSocketWrapper::IsConnectedAndIdle() const {
  if (transport_socket_)
    return transport_socket_->IsConnectedAndIdle();
  return false;
}

const NetLogWithSource& HttpProxyClientSocketWrapper::NetLog() const {
  return net_log_;
}

void HttpProxyClientSocketWrapper::SetSubresourceSpeculation() {
  // This flag isn't passed to reconnected sockets, as only the first connection
  // can be a preconnect.
  if (transport_socket_)
    transport_socket_->SetSubresourceSpeculation();
}

void HttpProxyClientSocketWrapper::SetOmniboxSpeculation() {
  // This flag isn't passed to reconnected sockets, as only the first connection
  // can be a preconnect.
  if (transport_socket_)
    transport_socket_->SetOmniboxSpeculation();
}

bool HttpProxyClientSocketWrapper::WasEverUsed() const {
  // TODO(mmenke):  This is a little weird.  Figure out if something else should
  // be done.
  if (transport_socket_)
    return transport_socket_->WasEverUsed();
  return false;
}

bool HttpProxyClientSocketWrapper::WasAlpnNegotiated() const {
  if (transport_socket_)
    return transport_socket_->WasAlpnNegotiated();
  return false;
}

NextProto HttpProxyClientSocketWrapper::GetNegotiatedProtocol() const {
  if (transport_socket_)
    return transport_socket_->GetNegotiatedProtocol();
  return kProtoUnknown;
}

bool HttpProxyClientSocketWrapper::GetSSLInfo(SSLInfo* ssl_info) {
  if (transport_socket_)
    return transport_socket_->GetSSLInfo(ssl_info);
  return false;
}

void HttpProxyClientSocketWrapper::GetConnectionAttempts(
    ConnectionAttempts* out) const {
  // TODO(mmenke): Not clear how reconnecting for auth fits into things.
  if (transport_socket_) {
    transport_socket_->GetConnectionAttempts(out);
  } else {
    out->clear();
  }
}

void HttpProxyClientSocketWrapper::ClearConnectionAttempts() {
  if (transport_socket_)
    transport_socket_->ClearConnectionAttempts();
}

void HttpProxyClientSocketWrapper::AddConnectionAttempts(
    const ConnectionAttempts& attempts) {
  if (transport_socket_)
    transport_socket_->AddConnectionAttempts(attempts);
}

int64_t HttpProxyClientSocketWrapper::GetTotalReceivedBytes() const {
  return transport_socket_->GetTotalReceivedBytes();
}

int HttpProxyClientSocketWrapper::Read(IOBuffer* buf,
                                       int buf_len,
                                       const CompletionCallback& callback) {
  if (transport_socket_)
    return transport_socket_->Read(buf, buf_len, callback);
  return ERR_SOCKET_NOT_CONNECTED;
}

int HttpProxyClientSocketWrapper::Write(IOBuffer* buf,
                                        int buf_len,
                                        const CompletionCallback& callback) {
  if (transport_socket_)
    return transport_socket_->Write(buf, buf_len, callback);
  return ERR_SOCKET_NOT_CONNECTED;
}

int HttpProxyClientSocketWrapper::SetReceiveBufferSize(int32_t size) {
  // TODO(mmenke):  Should this persist across reconnects?  Seems a little
  //     weird, and not done for normal reconnects.
  if (transport_socket_)
    return transport_socket_->SetReceiveBufferSize(size);
  return ERR_SOCKET_NOT_CONNECTED;
}

int HttpProxyClientSocketWrapper::SetSendBufferSize(int32_t size) {
  if (transport_socket_)
    return transport_socket_->SetSendBufferSize(size);
  return ERR_SOCKET_NOT_CONNECTED;
}

int HttpProxyClientSocketWrapper::GetPeerAddress(IPEndPoint* address) const {
  if (transport_socket_)
    return transport_socket_->GetPeerAddress(address);
  return ERR_SOCKET_NOT_CONNECTED;
}

int HttpProxyClientSocketWrapper::GetLocalAddress(IPEndPoint* address) const {
  if (transport_socket_)
    return transport_socket_->GetLocalAddress(address);
  return ERR_SOCKET_NOT_CONNECTED;
}

void HttpProxyClientSocketWrapper::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    connect_timer_.Stop();
    NotifyProxyDelegateOfCompletion(rv);
    // May delete |this|.
    base::ResetAndReturn(&connect_callback_).Run(rv);
  }
}

int HttpProxyClientSocketWrapper::DoLoop(int result) {
  DCHECK_NE(next_state_, STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_BEGIN_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoBeginConnect();
        break;
      case STATE_TCP_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoTransportConnect();
        break;
      case STATE_TCP_CONNECT_COMPLETE:
        rv = DoTransportConnectComplete(rv);
        break;
      case STATE_SSL_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoSSLConnect();
        break;
      case STATE_SSL_CONNECT_COMPLETE:
        rv = DoSSLConnectComplete(rv);
        break;
      case STATE_HTTP_PROXY_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoHttpProxyConnect();
        break;
      case STATE_HTTP_PROXY_CONNECT_COMPLETE:
        rv = DoHttpProxyConnectComplete(rv);
        break;
      case STATE_SPDY_PROXY_CREATE_STREAM:
        DCHECK_EQ(OK, rv);
        rv = DoSpdyProxyCreateStream();
        break;
      case STATE_SPDY_PROXY_CREATE_STREAM_COMPLETE:
        rv = DoSpdyProxyCreateStreamComplete(rv);
        break;
      case STATE_RESTART_WITH_AUTH:
        DCHECK_EQ(OK, rv);
        rv = DoRestartWithAuth();
        break;
      case STATE_RESTART_WITH_AUTH_COMPLETE:
        rv = DoRestartWithAuthComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
        rv = ERR_FAILED;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

int HttpProxyClientSocketWrapper::DoBeginConnect() {
  connect_start_time_ = base::TimeTicks::Now();
  SetConnectTimer(connect_timeout_duration_);
  if (transport_params_) {
    next_state_ = STATE_TCP_CONNECT;
  } else {
    next_state_ = STATE_SSL_CONNECT;
  }

  return OK;
}

int HttpProxyClientSocketWrapper::DoTransportConnect() {
  next_state_ = STATE_TCP_CONNECT_COMPLETE;
  transport_socket_handle_.reset(new ClientSocketHandle());
  return transport_socket_handle_->Init(
      group_name_, transport_params_, priority_, respect_limits_,
      base::Bind(&HttpProxyClientSocketWrapper::OnIOComplete,
                 base::Unretained(this)),
      transport_pool_, net_log_);
}

int HttpProxyClientSocketWrapper::DoTransportConnectComplete(int result) {
  if (result != OK) {
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Insecure.Error",
                               base::TimeTicks::Now() - connect_start_time_);
    return ERR_PROXY_CONNECTION_FAILED;
  }

  // Reset the timer to just the length of time allowed for HttpProxy handshake
  // so that a fast TCP connection plus a slow HttpProxy failure doesn't take
  // longer to timeout than it should.
  SetConnectTimer(proxy_negotiation_timeout_duration_);

  next_state_ = STATE_HTTP_PROXY_CONNECT;
  return result;
}

int HttpProxyClientSocketWrapper::DoSSLConnect() {
  if (tunnel_) {
    SpdySessionKey key(GetDestination().host_port_pair(), ProxyServer::Direct(),
                       PRIVACY_MODE_DISABLED);
    if (spdy_session_pool_->FindAvailableSession(
            key, GURL(),
            /* enable_ip_based_pooling = */ true, net_log_)) {
      using_spdy_ = true;
      next_state_ = STATE_SPDY_PROXY_CREATE_STREAM;
      return OK;
    }
  }
  next_state_ = STATE_SSL_CONNECT_COMPLETE;
  transport_socket_handle_.reset(new ClientSocketHandle());
  return transport_socket_handle_->Init(
      group_name_, ssl_params_, priority_, respect_limits_,
      base::Bind(&HttpProxyClientSocketWrapper::OnIOComplete,
                 base::Unretained(this)),
      ssl_pool_, net_log_);
}

int HttpProxyClientSocketWrapper::DoSSLConnectComplete(int result) {
  if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    DCHECK(
        transport_socket_handle_->ssl_error_response_info().cert_request_info);
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Secure.Error",
                               base::TimeTicks::Now() - connect_start_time_);
    error_response_info_.reset(new HttpResponseInfo(
        transport_socket_handle_->ssl_error_response_info()));
    error_response_info_->cert_request_info->is_proxy = true;
    return result;
  }

  if (IsCertificateError(result)) {
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Secure.Error",
                               base::TimeTicks::Now() - connect_start_time_);
    if (ssl_params_->load_flags() & LOAD_IGNORE_ALL_CERT_ERRORS) {
      result = OK;
    } else {
      // TODO(rch): allow the user to deal with proxy cert errors in the
      // same way as server cert errors.
      transport_socket_handle_->socket()->Disconnect();
      return ERR_PROXY_CERTIFICATE_INVALID;
    }
  }
  // A SPDY session to the proxy completed prior to resolving the proxy
  // hostname. Surface this error, and allow the delegate to retry.
  // See crbug.com/334413.
  if (result == ERR_SPDY_SESSION_ALREADY_EXISTS) {
    DCHECK(!transport_socket_handle_->socket());
    return ERR_SPDY_SESSION_ALREADY_EXISTS;
  }
  if (result < 0) {
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Secure.Error",
                               base::TimeTicks::Now() - connect_start_time_);
    if (transport_socket_handle_->socket())
      transport_socket_handle_->socket()->Disconnect();
    return ERR_PROXY_CONNECTION_FAILED;
  }

  SSLClientSocket* ssl =
      static_cast<SSLClientSocket*>(transport_socket_handle_->socket());
  negotiated_protocol_ = ssl->GetNegotiatedProtocol();
  using_spdy_ = negotiated_protocol_ == kProtoHTTP2;

  // Reset the timer to just the length of time allowed for HttpProxy handshake
  // so that a fast SSL connection plus a slow HttpProxy failure doesn't take
  // longer to timeout than it should.
  SetConnectTimer(proxy_negotiation_timeout_duration_);

  // TODO(rch): If we ever decide to implement a "trusted" SPDY proxy
  // (one that we speak SPDY over SSL to, but to which we send HTTPS
  // request directly instead of through CONNECT tunnels, then we
  // need to add a predicate to this if statement so we fall through
  // to the else case. (HttpProxyClientSocket currently acts as
  // a "trusted" SPDY proxy).
  if (using_spdy_ && tunnel_) {
    next_state_ = STATE_SPDY_PROXY_CREATE_STREAM;
  } else {
    next_state_ = STATE_HTTP_PROXY_CONNECT;
  }
  return result;
}

int HttpProxyClientSocketWrapper::DoHttpProxyConnect() {
  next_state_ = STATE_HTTP_PROXY_CONNECT_COMPLETE;

  if (transport_params_) {
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Insecure.Success",
                               base::TimeTicks::Now() - connect_start_time_);
  } else {
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Secure.Success",
                               base::TimeTicks::Now() - connect_start_time_);
  }

  // Add a HttpProxy connection on top of the tcp socket.
  transport_socket_.reset(new HttpProxyClientSocket(
      transport_socket_handle_.release(), user_agent_, endpoint_,
      GetDestination().host_port_pair(), http_auth_controller_.get(), tunnel_,
      using_spdy_, negotiated_protocol_, proxy_delegate_,
      ssl_params_.get() != nullptr));
  return transport_socket_->Connect(base::Bind(
      &HttpProxyClientSocketWrapper::OnIOComplete, base::Unretained(this)));
}

int HttpProxyClientSocketWrapper::DoHttpProxyConnectComplete(int result) {
  if (result == ERR_HTTP_1_1_REQUIRED)
    return ERR_PROXY_HTTP_1_1_REQUIRED;

  return result;
}

int HttpProxyClientSocketWrapper::DoSpdyProxyCreateStream() {
  DCHECK(using_spdy_);
  DCHECK(tunnel_);
  SpdySessionKey key(GetDestination().host_port_pair(), ProxyServer::Direct(),
                     PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session =
      spdy_session_pool_->FindAvailableSession(
          key, GURL(),
          /* enable_ip_based_pooling = */ true, net_log_);
  // It's possible that a session to the proxy has recently been created
  if (spdy_session) {
    if (transport_socket_handle_.get()) {
      if (transport_socket_handle_->socket())
        transport_socket_handle_->socket()->Disconnect();
      transport_socket_handle_->Reset();
    }
  } else {
    // Create a session direct to the proxy itself
    spdy_session = spdy_session_pool_->CreateAvailableSessionFromSocket(
        key, std::move(transport_socket_handle_), net_log_);
    DCHECK(spdy_session);
  }

  next_state_ = STATE_SPDY_PROXY_CREATE_STREAM_COMPLETE;
  return spdy_stream_request_.StartRequest(
      SPDY_BIDIRECTIONAL_STREAM, spdy_session,
      GURL("https://" + endpoint_.ToString()), priority_,
      spdy_session->net_log(),
      base::Bind(&HttpProxyClientSocketWrapper::OnIOComplete,
                 base::Unretained(this)));
}

int HttpProxyClientSocketWrapper::DoSpdyProxyCreateStreamComplete(int result) {
  if (result < 0)
    return result;

  next_state_ = STATE_HTTP_PROXY_CONNECT_COMPLETE;
  base::WeakPtr<SpdyStream> stream = spdy_stream_request_.ReleaseStream();
  DCHECK(stream.get());
  // |transport_socket_| will set itself as |stream|'s delegate.
  transport_socket_.reset(new SpdyProxyClientSocket(
      stream, user_agent_, endpoint_, GetDestination().host_port_pair(),
      net_log_, http_auth_controller_.get()));
  return transport_socket_->Connect(base::Bind(
      &HttpProxyClientSocketWrapper::OnIOComplete, base::Unretained(this)));
}

int HttpProxyClientSocketWrapper::DoRestartWithAuth() {
  DCHECK(transport_socket_);

  next_state_ = STATE_RESTART_WITH_AUTH_COMPLETE;
  return transport_socket_->RestartWithAuth(base::Bind(
      &HttpProxyClientSocketWrapper::OnIOComplete, base::Unretained(this)));
}

int HttpProxyClientSocketWrapper::DoRestartWithAuthComplete(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);

  // If the connection could not be reused to attempt to send proxy auth
  // credentials, try reconnecting. Do not reset the HttpAuthController in this
  // case; the server may, for instance, send "Proxy-Connection: close" and
  // expect that each leg of the authentication progress on separate
  // connections.
  bool reconnect = result == ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH;

  // If auth credentials were sent but the connection was closed, the server may
  // have timed out while the user was selecting credentials. Retry once.
  if (!has_restarted_ &&
      (result == ERR_CONNECTION_CLOSED || result == ERR_CONNECTION_RESET ||
       result == ERR_CONNECTION_ABORTED ||
       result == ERR_SOCKET_NOT_CONNECTED)) {
    reconnect = true;
    has_restarted_ = true;

    // Release any auth state bound to the connection. The new connection will
    // start the current scheme from scratch.
    if (http_auth_controller_)
      http_auth_controller_->OnConnectionClosed();
  }

  if (reconnect) {
    // Attempt to create a new one.
    transport_socket_.reset();

    // Reconnect with HIGHEST priority to get in front of other requests that
    // don't yet have the information |http_auth_controller_| does.
    // TODO(mmenke): This may still result in waiting in line, if there are
    //               other HIGHEST priority requests. Consider a workaround for
    //               that. Starting the new request before releasing the old
    //               socket and using RespectLimits::Disabled would work,
    //               without exceding the the socket pool limits (Since the old
    //               socket would free up the extra socket slot when destroyed).
    priority_ = HIGHEST;
    next_state_ = STATE_BEGIN_CONNECT;
    return OK;
  }

  return result;
}

void HttpProxyClientSocketWrapper::NotifyProxyDelegateOfCompletion(int result) {
  if (!proxy_delegate_)
    return;

  const HostPortPair& proxy_server = GetDestination().host_port_pair();
  proxy_delegate_->OnTunnelConnectCompleted(endpoint_, proxy_server, result);
}

void HttpProxyClientSocketWrapper::SetConnectTimer(base::TimeDelta delay) {
  connect_timer_.Stop();
  connect_timer_.Start(FROM_HERE, delay, this,
                       &HttpProxyClientSocketWrapper::ConnectTimeout);
}

void HttpProxyClientSocketWrapper::ConnectTimeout() {
  // Timer shouldn't be running if next_state_ is STATE_NONE.
  DCHECK_NE(STATE_NONE, next_state_);
  DCHECK(!connect_callback_.is_null());

  if (next_state_ == STATE_TCP_CONNECT_COMPLETE ||
      next_state_ == STATE_SSL_CONNECT_COMPLETE) {
    if (transport_params_) {
      UMA_HISTOGRAM_MEDIUM_TIMES(
          "Net.HttpProxy.ConnectLatency.Insecure.TimedOut",
          base::TimeTicks::Now() - connect_start_time_);
    } else {
      UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpProxy.ConnectLatency.Secure.TimedOut",
                                 base::TimeTicks::Now() - connect_start_time_);
    }
  }

  NotifyProxyDelegateOfCompletion(ERR_CONNECTION_TIMED_OUT);

  CompletionCallback callback = connect_callback_;
  Disconnect();
  callback.Run(ERR_CONNECTION_TIMED_OUT);
}

const HostResolver::RequestInfo&
HttpProxyClientSocketWrapper::GetDestination() {
  if (transport_params_) {
    return transport_params_->destination();
  } else {
    return ssl_params_->GetDirectConnectionParams()->destination();
  }
}

}  // namespace net
