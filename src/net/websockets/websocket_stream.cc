// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_stream.h"

#include <utility>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/load_flags.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/websockets/websocket_errors.h"
#include "net/websockets/websocket_event_interface.h"
#include "net/websockets/websocket_handshake_constants.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "net/websockets/websocket_handshake_stream_create_helper.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

// The timeout duration of WebSocket handshake.
// It is defined as the same value as the TCP connection timeout value in
// net/socket/websocket_transport_client_socket_pool.cc to make it hard for
// JavaScript programs to recognize the timeout cause.
const int kHandshakeTimeoutIntervalInSeconds = 240;

class StreamRequestImpl;

class Delegate : public URLRequest::Delegate {
 public:
  enum HandshakeResult {
    INCOMPLETE,
    CONNECTED,
    FAILED,
    NUM_HANDSHAKE_RESULT_TYPES,
  };

  explicit Delegate(StreamRequestImpl* owner)
      : owner_(owner), result_(INCOMPLETE) {}
  ~Delegate() override {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.WebSocket.HandshakeResult", result_, NUM_HANDSHAKE_RESULT_TYPES);
  }

  // Implementation of URLRequest::Delegate methods.
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override;

  void OnResponseStarted(URLRequest* request) override;

  void OnAuthRequired(URLRequest* request,
                      AuthChallengeInfo* auth_info) override;

  void OnCertificateRequested(URLRequest* request,
                              SSLCertRequestInfo* cert_request_info) override;

  void OnSSLCertificateError(URLRequest* request,
                             const SSLInfo& ssl_info,
                             bool fatal) override;

  void OnReadCompleted(URLRequest* request, int bytes_read) override;

 private:
  StreamRequestImpl* owner_;
  HandshakeResult result_;
};

class StreamRequestImpl : public WebSocketStreamRequest {
 public:
  StreamRequestImpl(
      const GURL& url,
      const URLRequestContext* context,
      const url::Origin& origin,
      scoped_ptr<WebSocketStream::ConnectDelegate> connect_delegate,
      scoped_ptr<WebSocketHandshakeStreamCreateHelper> create_helper)
      : delegate_(new Delegate(this)),
        url_request_(
            context->CreateRequest(url, DEFAULT_PRIORITY, delegate_.get())),
        connect_delegate_(std::move(connect_delegate)),
        create_helper_(create_helper.release()) {
    create_helper_->set_failure_message(&failure_message_);
    HttpRequestHeaders headers;
    headers.SetHeader(websockets::kUpgrade, websockets::kWebSocketLowercase);
    headers.SetHeader(HttpRequestHeaders::kConnection, websockets::kUpgrade);
    headers.SetHeader(HttpRequestHeaders::kOrigin, origin.Serialize());
    headers.SetHeader(websockets::kSecWebSocketVersion,
                      websockets::kSupportedVersion);
    url_request_->SetExtraRequestHeaders(headers);

    // This passes the ownership of |create_helper_| to |url_request_|.
    url_request_->SetUserData(
        WebSocketHandshakeStreamBase::CreateHelper::DataKey(),
        create_helper_);
    url_request_->SetLoadFlags(LOAD_DISABLE_CACHE | LOAD_BYPASS_CACHE);
  }

  // Destroying this object destroys the URLRequest, which cancels the request
  // and so terminates the handshake if it is incomplete.
  ~StreamRequestImpl() override {}

  void Start(scoped_ptr<base::Timer> timer) {
    DCHECK(timer);
    base::TimeDelta timeout(base::TimeDelta::FromSeconds(
        kHandshakeTimeoutIntervalInSeconds));
    timer_ = std::move(timer);
    timer_->Start(FROM_HERE, timeout,
                  base::Bind(&StreamRequestImpl::OnTimeout,
                             base::Unretained(this)));
    url_request_->Start();
  }

  void PerformUpgrade() {
    DCHECK(timer_);
    timer_->Stop();
    connect_delegate_->OnSuccess(create_helper_->Upgrade());
  }

  std::string FailureMessageFromNetError() {
    int error = url_request_->status().error();
    if (error == ERR_TUNNEL_CONNECTION_FAILED) {
      // This error is common and confusing, so special-case it.
      // TODO(ricea): Include the HostPortPair of the selected proxy server in
      // the error message. This is not currently possible because it isn't set
      // in HttpResponseInfo when a ERR_TUNNEL_CONNECTION_FAILED error happens.
      return "Establishing a tunnel via proxy server failed.";
    } else {
      return std::string("Error in connection establishment: ") +
             ErrorToString(url_request_->status().error());
    }
  }

  void ReportFailure() {
    DCHECK(timer_);
    timer_->Stop();
    if (failure_message_.empty()) {
      switch (url_request_->status().status()) {
        case URLRequestStatus::SUCCESS:
        case URLRequestStatus::IO_PENDING:
          break;
        case URLRequestStatus::CANCELED:
          if (url_request_->status().error() == ERR_TIMED_OUT)
            failure_message_ = "WebSocket opening handshake timed out";
          else
            failure_message_ = "WebSocket opening handshake was canceled";
          break;
        case URLRequestStatus::FAILED:
          failure_message_ = FailureMessageFromNetError();
          break;
      }
    }
    ReportFailureWithMessage(failure_message_);
  }

  void ReportFailureWithMessage(const std::string& failure_message) {
    connect_delegate_->OnFailure(failure_message);
  }

  void OnFinishOpeningHandshake() {
    WebSocketDispatchOnFinishOpeningHandshake(connect_delegate(),
                                              url_request_->url(),
                                              url_request_->response_headers(),
                                              url_request_->response_time());
  }

  WebSocketStream::ConnectDelegate* connect_delegate() const {
    return connect_delegate_.get();
  }

  void OnTimeout() {
    url_request_->CancelWithError(ERR_TIMED_OUT);
  }

 private:
  // |delegate_| needs to be declared before |url_request_| so that it gets
  // initialised first.
  scoped_ptr<Delegate> delegate_;

  // Deleting the StreamRequestImpl object deletes this URLRequest object,
  // cancelling the whole connection.
  scoped_ptr<URLRequest> url_request_;

  scoped_ptr<WebSocketStream::ConnectDelegate> connect_delegate_;

  // Owned by the URLRequest.
  WebSocketHandshakeStreamCreateHelper* create_helper_;

  // The failure message supplied by WebSocketBasicHandshakeStream, if any.
  std::string failure_message_;

  // A timer for handshake timeout.
  scoped_ptr<base::Timer> timer_;
};

class SSLErrorCallbacks : public WebSocketEventInterface::SSLErrorCallbacks {
 public:
  explicit SSLErrorCallbacks(URLRequest* url_request)
      : url_request_(url_request) {}

  void CancelSSLRequest(int error, const SSLInfo* ssl_info) override {
    if (ssl_info) {
      url_request_->CancelWithSSLError(error, *ssl_info);
    } else {
      url_request_->CancelWithError(error);
    }
  }

  void ContinueSSLRequest() override {
    url_request_->ContinueDespiteLastError();
  }

 private:
  URLRequest* url_request_;
};

void Delegate::OnReceivedRedirect(URLRequest* request,
                                  const RedirectInfo& redirect_info,
                                  bool* defer_redirect) {
  // This code should never be reached for externally generated redirects,
  // as WebSocketBasicHandshakeStream is responsible for filtering out
  // all response codes besides 101, 401, and 407. As such, the URLRequest
  // should never see a redirect sent over the network. However, internal
  // redirects also result in this method being called, such as those
  // caused by HSTS.
  // Because it's security critical to prevent externally-generated
  // redirects in WebSockets, perform additional checks to ensure this
  // is only internal.
  GURL::Replacements replacements;
  replacements.SetSchemeStr("wss");
  GURL expected_url = request->original_url().ReplaceComponents(replacements);
  if (redirect_info.new_method != "GET" ||
      redirect_info.new_url != expected_url) {
    // This should not happen.
    DLOG(FATAL) << "Unauthorized WebSocket redirect to "
                << redirect_info.new_method << " "
                << redirect_info.new_url.spec();
    request->Cancel();
  }
}

void Delegate::OnResponseStarted(URLRequest* request) {
  // All error codes, including OK and ABORTED, as with
  // Net.ErrorCodesForMainFrame3
  UMA_HISTOGRAM_SPARSE_SLOWLY("Net.WebSocket.ErrorCodes",
                              -request->status().error());
  if (!request->status().is_success()) {
    DVLOG(3) << "OnResponseStarted (request failed)";
    owner_->ReportFailure();
    return;
  }
  const int response_code = request->GetResponseCode();
  DVLOG(3) << "OnResponseStarted (response code " << response_code << ")";
  switch (response_code) {
    case HTTP_SWITCHING_PROTOCOLS:
      result_ = CONNECTED;
      owner_->PerformUpgrade();
      return;

    case HTTP_UNAUTHORIZED:
      result_ = FAILED;
      owner_->OnFinishOpeningHandshake();
      owner_->ReportFailureWithMessage(
          "HTTP Authentication failed; no valid credentials available");
      return;

    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
      result_ = FAILED;
      owner_->OnFinishOpeningHandshake();
      owner_->ReportFailureWithMessage("Proxy authentication failed");
      return;

    default:
      result_ = FAILED;
      owner_->ReportFailure();
  }
}

void Delegate::OnAuthRequired(URLRequest* request,
                              AuthChallengeInfo* auth_info) {
  // This should only be called if credentials are not already stored.
  request->CancelAuth();
}

void Delegate::OnCertificateRequested(URLRequest* request,
                                      SSLCertRequestInfo* cert_request_info) {
  // This method is called when a client certificate is requested, and the
  // request context does not already contain a client certificate selection for
  // the endpoint. In this case, a main frame resource request would pop-up UI
  // to permit selection of a client certificate, but since WebSockets are
  // sub-resources they should not pop-up UI and so there is nothing more we can
  // do.
  request->Cancel();
}

void Delegate::OnSSLCertificateError(URLRequest* request,
                                     const SSLInfo& ssl_info,
                                     bool fatal) {
  owner_->connect_delegate()->OnSSLCertificateError(
      scoped_ptr<WebSocketEventInterface::SSLErrorCallbacks>(
          new SSLErrorCallbacks(request)),
      ssl_info,
      fatal);
}

void Delegate::OnReadCompleted(URLRequest* request, int bytes_read) {
  NOTREACHED();
}

}  // namespace

WebSocketStreamRequest::~WebSocketStreamRequest() {}

WebSocketStream::WebSocketStream() {}
WebSocketStream::~WebSocketStream() {}

WebSocketStream::ConnectDelegate::~ConnectDelegate() {}

scoped_ptr<WebSocketStreamRequest> WebSocketStream::CreateAndConnectStream(
    const GURL& socket_url,
    const std::vector<std::string>& requested_subprotocols,
    const url::Origin& origin,
    URLRequestContext* url_request_context,
    const BoundNetLog& net_log,
    scoped_ptr<ConnectDelegate> connect_delegate) {
  scoped_ptr<WebSocketHandshakeStreamCreateHelper> create_helper(
      new WebSocketHandshakeStreamCreateHelper(connect_delegate.get(),
                                               requested_subprotocols));
  scoped_ptr<StreamRequestImpl> request(new StreamRequestImpl(
      socket_url, url_request_context, origin, std::move(connect_delegate),
      std::move(create_helper)));
  request->Start(scoped_ptr<base::Timer>(new base::Timer(false, false)));
  return std::move(request);
}

// This is declared in websocket_test_util.h.
scoped_ptr<WebSocketStreamRequest> CreateAndConnectStreamForTesting(
    const GURL& socket_url,
    scoped_ptr<WebSocketHandshakeStreamCreateHelper> create_helper,
    const url::Origin& origin,
    URLRequestContext* url_request_context,
    const BoundNetLog& net_log,
    scoped_ptr<WebSocketStream::ConnectDelegate> connect_delegate,
    scoped_ptr<base::Timer> timer) {
  scoped_ptr<StreamRequestImpl> request(new StreamRequestImpl(
      socket_url, url_request_context, origin, std::move(connect_delegate),
      std::move(create_helper)));
  request->Start(std::move(timer));
  return std::move(request);
}

void WebSocketDispatchOnFinishOpeningHandshake(
    WebSocketStream::ConnectDelegate* connect_delegate,
    const GURL& url,
    const scoped_refptr<HttpResponseHeaders>& headers,
    base::Time response_time) {
  DCHECK(connect_delegate);
  if (headers.get()) {
    connect_delegate->OnFinishOpeningHandshake(make_scoped_ptr(
        new WebSocketHandshakeResponseInfo(url,
                                           headers->response_code(),
                                           headers->GetStatusText(),
                                           headers,
                                           response_time)));
  }
}

}  // namespace net
