// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_job.h"

#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/power_monitor/power_monitor.h"
#include "base/profiler/scoped_tracker.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/base/auth.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/proxy/proxy_server.h"
#include "net/url_request/url_request_context.h"

namespace net {

namespace {

// Callback for TYPE_URL_REQUEST_FILTERS_SET net-internals event.
std::unique_ptr<base::Value> SourceStreamSetCallback(
    SourceStream* source_stream,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetString("filters", source_stream->Description());
  return std::move(event_params);
}

std::string ComputeMethodForRedirect(const std::string& method,
                                     int http_status_code) {
  // For 303 redirects, all request methods except HEAD are converted to GET,
  // as per the latest httpbis draft.  The draft also allows POST requests to
  // be converted to GETs when following 301/302 redirects, for historical
  // reasons. Most major browsers do this and so shall we.  Both RFC 2616 and
  // the httpbis draft say to prompt the user to confirm the generation of new
  // requests, other than GET and HEAD requests, but IE omits these prompts and
  // so shall we.
  // See:
  // https://tools.ietf.org/html/draft-ietf-httpbis-p2-semantics-17#section-7.3
  if ((http_status_code == 303 && method != "HEAD") ||
      ((http_status_code == 301 || http_status_code == 302) &&
       method == "POST")) {
    return "GET";
  }
  return method;
}

// A redirect response can contain a Referrer-Policy header
// (https://w3c.github.io/webappsec-referrer-policy/). This function
// checks for a Referrer-Policy header, and parses it if
// present. Returns the referrer policy that should be used for the
// request.
URLRequest::ReferrerPolicy ProcessReferrerPolicyHeaderOnRedirect(
    URLRequest* request) {
  URLRequest::ReferrerPolicy new_policy = request->referrer_policy();

  std::string referrer_policy_header;
  request->GetResponseHeaderByName("Referrer-Policy", &referrer_policy_header);
  std::vector<std::string> policy_tokens =
      base::SplitString(referrer_policy_header, ",", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);

  UMA_HISTOGRAM_BOOLEAN("Net.URLRequest.ReferrerPolicyHeaderPresentOnRedirect",
                        !policy_tokens.empty());

  // Per https://w3c.github.io/webappsec-referrer-policy/#unknown-policy-values,
  // use the last recognized policy value, and ignore unknown policies.
  for (const auto& token : policy_tokens) {
    if (base::CompareCaseInsensitiveASCII(token, "no-referrer") == 0) {
      new_policy = URLRequest::NO_REFERRER;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(token,
                                          "no-referrer-when-downgrade") == 0) {
      new_policy =
          URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(token, "origin") == 0) {
      new_policy = URLRequest::ORIGIN;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(token, "origin-when-cross-origin") ==
        0) {
      new_policy = URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(token, "unsafe-url") == 0) {
      new_policy = URLRequest::NEVER_CLEAR_REFERRER;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(token, "same-origin") == 0) {
      new_policy = URLRequest::CLEAR_REFERRER_ON_TRANSITION_CROSS_ORIGIN;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(token, "strict-origin") == 0) {
      new_policy =
          URLRequest::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE;
      continue;
    }

    if (base::CompareCaseInsensitiveASCII(
            token, "strict-origin-when-cross-origin") == 0) {
      new_policy =
          URLRequest::REDUCE_REFERRER_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN;
      continue;
    }
  }
  return new_policy;
}

}  // namespace

// Each SourceStreams own the previous SourceStream in the chain, but the
// ultimate source is URLRequestJob, which has other ownership semantics, so
// this class is a proxy for URLRequestJob that is owned by the first stream
// (in dataflow order).
class URLRequestJob::URLRequestJobSourceStream : public SourceStream {
 public:
  explicit URLRequestJobSourceStream(URLRequestJob* job)
      : SourceStream(SourceStream::TYPE_NONE), job_(job) {
    DCHECK(job_);
  }

  ~URLRequestJobSourceStream() override {}

  // SourceStream implementation:
  int Read(IOBuffer* dest_buffer,
           int buffer_size,
           const CompletionCallback& callback) override {
    DCHECK(job_);
    return job_->ReadRawDataHelper(dest_buffer, buffer_size, callback);
  }

  std::string Description() const override { return std::string(); }

 private:
  // It is safe to keep a raw pointer because |job_| owns the last stream which
  // indirectly owns |this|. Therefore, |job_| will not be destroyed when |this|
  // is alive.
  URLRequestJob* const job_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestJobSourceStream);
};

URLRequestJob::URLRequestJob(URLRequest* request,
                             NetworkDelegate* network_delegate)
    : request_(request),
      done_(false),
      prefilter_bytes_read_(0),
      postfilter_bytes_read_(0),
      has_handled_response_(false),
      expected_content_size_(-1),
      network_delegate_(network_delegate),
      last_notified_total_received_bytes_(0),
      last_notified_total_sent_bytes_(0),
      weak_factory_(this) {
  base::PowerMonitor* power_monitor = base::PowerMonitor::Get();
  if (power_monitor)
    power_monitor->AddObserver(this);
}

URLRequestJob::~URLRequestJob() {
  base::PowerMonitor* power_monitor = base::PowerMonitor::Get();
  if (power_monitor)
    power_monitor->RemoveObserver(this);
}

void URLRequestJob::SetUpload(UploadDataStream* upload) {
}

void URLRequestJob::SetExtraRequestHeaders(const HttpRequestHeaders& headers) {
}

void URLRequestJob::SetPriority(RequestPriority priority) {
}

void URLRequestJob::Kill() {
  weak_factory_.InvalidateWeakPtrs();
  // Make sure the URLRequest is notified that the job is done.  This assumes
  // that the URLRequest took care of setting its error status before calling
  // Kill().
  // TODO(mmenke):  The URLRequest is currently deleted before this method
  // invokes its async callback whenever this is called by the URLRequest.
  // Try to simplify how cancellation works.
  NotifyCanceled();
}

// This method passes reads down the filter chain, where they eventually end up
// at URLRequestJobSourceStream::Read, which calls back into
// URLRequestJob::ReadRawData.
int URLRequestJob::Read(IOBuffer* buf, int buf_size) {
  DCHECK(buf);

  pending_read_buffer_ = buf;
  int result = source_stream_->Read(
      buf, buf_size, base::Bind(&URLRequestJob::SourceStreamReadComplete,
                                weak_factory_.GetWeakPtr(), false));
  if (result == ERR_IO_PENDING)
    return ERR_IO_PENDING;

  SourceStreamReadComplete(true, result);
  return result;
}

void URLRequestJob::StopCaching() {
  // Nothing to do here.
}

bool URLRequestJob::GetFullRequestHeaders(HttpRequestHeaders* headers) const {
  // Most job types don't send request headers.
  return false;
}

int64_t URLRequestJob::GetTotalReceivedBytes() const {
  return 0;
}

int64_t URLRequestJob::GetTotalSentBytes() const {
  return 0;
}

LoadState URLRequestJob::GetLoadState() const {
  return LOAD_STATE_IDLE;
}

bool URLRequestJob::GetCharset(std::string* charset) {
  return false;
}

void URLRequestJob::GetResponseInfo(HttpResponseInfo* info) {
}

void URLRequestJob::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  // Only certain request types return more than just request start times.
}

bool URLRequestJob::GetRemoteEndpoint(IPEndPoint* endpoint) const {
  return false;
}

void URLRequestJob::PopulateNetErrorDetails(NetErrorDetails* details) const {
  return;
}

bool URLRequestJob::IsRedirectResponse(GURL* location,
                                       int* http_status_code) {
  // For non-HTTP jobs, headers will be null.
  HttpResponseHeaders* headers = request_->response_headers();
  if (!headers)
    return false;

  std::string value;
  if (!headers->IsRedirect(&value))
    return false;

  *location = request_->url().Resolve(value);
  *http_status_code = headers->response_code();
  return true;
}

bool URLRequestJob::CopyFragmentOnRedirect(const GURL& location) const {
  return true;
}

bool URLRequestJob::IsSafeRedirect(const GURL& location) {
  return true;
}

bool URLRequestJob::NeedsAuth() {
  return false;
}

void URLRequestJob::GetAuthChallengeInfo(
    scoped_refptr<AuthChallengeInfo>* auth_info) {
  // This will only be called if NeedsAuth() returns true, in which
  // case the derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::SetAuth(const AuthCredentials& credentials) {
  // This will only be called if NeedsAuth() returns true, in which
  // case the derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::CancelAuth() {
  // This will only be called if NeedsAuth() returns true, in which
  // case the derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::ContinueWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key) {
  // The derived class should implement this!
  NOTREACHED();
}

void URLRequestJob::ContinueDespiteLastError() {
  // Implementations should know how to recover from errors they generate.
  // If this code was reached, we are trying to recover from an error that
  // we don't know how to recover from.
  NOTREACHED();
}

void URLRequestJob::FollowDeferredRedirect() {
  // OnReceivedRedirect must have been called.
  DCHECK_NE(-1, deferred_redirect_info_.status_code);

  // It is possible that FollowRedirect will delete |this|, so it is not safe to
  // pass along a reference to |deferred_redirect_info_|.
  RedirectInfo redirect_info = deferred_redirect_info_;
  deferred_redirect_info_ = RedirectInfo();
  FollowRedirect(redirect_info);
}

bool URLRequestJob::GetMimeType(std::string* mime_type) const {
  return false;
}

int URLRequestJob::GetResponseCode() const {
  HttpResponseHeaders* headers = request_->response_headers();
  if (!headers)
    return -1;
  return headers->response_code();
}

HostPortPair URLRequestJob::GetSocketAddress() const {
  return HostPortPair();
}

void URLRequestJob::OnSuspend() {
  // Most errors generated by the Job come as the result of the one current
  // operation the job is waiting on returning an error. This event is unusual
  // in that the Job may have another operation ongoing, or the Job may be idle
  // and waiting on the next call.
  //
  // Need to cancel through the request to make sure everything is notified
  // of the failure (Particularly that the NetworkDelegate, which the Job may be
  // waiting on, is notified synchronously) and torn down correctly.
  //
  // TODO(mmenke): This should probably fail the request with
  //               NETWORK_IO_SUSPENDED instead.
  request_->Cancel();
}

void URLRequestJob::NotifyURLRequestDestroyed() {
}

void URLRequestJob::GetConnectionAttempts(ConnectionAttempts* out) const {
  out->clear();
}

// static
GURL URLRequestJob::ComputeReferrerForPolicy(URLRequest::ReferrerPolicy policy,
                                             const GURL& original_referrer,
                                             const GURL& destination) {
  bool secure_referrer_but_insecure_destination =
      original_referrer.SchemeIsCryptographic() &&
      !destination.SchemeIsCryptographic();
  url::Origin referrer_origin(original_referrer);
  bool same_origin = referrer_origin.IsSameOriginWith(url::Origin(destination));
  switch (policy) {
    case URLRequest::CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE:
      return secure_referrer_but_insecure_destination ? GURL()
                                                      : original_referrer;

    case URLRequest::REDUCE_REFERRER_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN:
      if (same_origin) {
        return original_referrer;
      } else if (secure_referrer_but_insecure_destination) {
        return GURL();
      } else {
        return referrer_origin.GetURL();
      }

    case URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN:
      return same_origin ? original_referrer : referrer_origin.GetURL();

    case URLRequest::NEVER_CLEAR_REFERRER:
      return original_referrer;
    case URLRequest::ORIGIN:
      return referrer_origin.GetURL();
    case URLRequest::CLEAR_REFERRER_ON_TRANSITION_CROSS_ORIGIN:
      if (same_origin)
        return original_referrer;
      return GURL();
    case URLRequest::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE:
      if (secure_referrer_but_insecure_destination)
        return GURL();
      return referrer_origin.GetURL();
    case URLRequest::NO_REFERRER:
      return GURL();
    case URLRequest::MAX_REFERRER_POLICY:
      NOTREACHED();
      return GURL();
  }

  NOTREACHED();
  return GURL();
}

void URLRequestJob::NotifyCertificateRequested(
    SSLCertRequestInfo* cert_request_info) {
  request_->NotifyCertificateRequested(cert_request_info);
}

void URLRequestJob::NotifySSLCertificateError(const SSLInfo& ssl_info,
                                              bool fatal) {
  request_->NotifySSLCertificateError(ssl_info, fatal);
}

bool URLRequestJob::CanGetCookies(const CookieList& cookie_list) const {
  return request_->CanGetCookies(cookie_list);
}

bool URLRequestJob::CanSetCookie(const std::string& cookie_line,
                                 CookieOptions* options) const {
  return request_->CanSetCookie(cookie_line, options);
}

bool URLRequestJob::CanEnablePrivacyMode() const {
  return request_->CanEnablePrivacyMode();
}

void URLRequestJob::NotifyHeadersComplete() {
  if (has_handled_response_)
    return;

  // The URLRequest status should still be IO_PENDING, which it was set to
  // before the URLRequestJob was started.  On error or cancellation, this
  // method should not be called.
  DCHECK(request_->status().is_io_pending());

  // Initialize to the current time, and let the subclass optionally override
  // the time stamps if it has that information.  The default request_time is
  // set by URLRequest before it calls our Start method.
  request_->response_info_.response_time = base::Time::Now();
  GetResponseInfo(&request_->response_info_);

  MaybeNotifyNetworkBytes();
  request_->OnHeadersComplete();

  GURL new_location;
  int http_status_code;

  if (IsRedirectResponse(&new_location, &http_status_code)) {
    // Redirect response bodies are not read. Notify the transaction
    // so it does not treat being stopped as an error.
    DoneReadingRedirectResponse();

    // Invalid redirect targets are failed early before
    // NotifyReceivedRedirect. This means the delegate can assume that, if it
    // accepts the redirect, future calls to OnResponseStarted correspond to
    // |redirect_info.new_url|.
    int redirect_valid = CanFollowRedirect(new_location);
    if (redirect_valid != OK) {
      OnDone(URLRequestStatus::FromError(redirect_valid), true);
      return;
    }

    // When notifying the URLRequest::Delegate, it can destroy the request,
    // which will destroy |this|.  After calling to the URLRequest::Delegate,
    // pointer must be checked to see if |this| still exists, and if not, the
    // code must return immediately.
    base::WeakPtr<URLRequestJob> weak_this(weak_factory_.GetWeakPtr());

    RedirectInfo redirect_info =
        ComputeRedirectInfo(new_location, http_status_code);
    bool defer_redirect = false;
    request_->NotifyReceivedRedirect(redirect_info, &defer_redirect);

    // Ensure that the request wasn't detached, destroyed, or canceled in
    // NotifyReceivedRedirect.
    if (!weak_this || !request_->status().is_success())
      return;

    if (defer_redirect) {
      deferred_redirect_info_ = redirect_info;
    } else {
      FollowRedirect(redirect_info);
    }
    return;
  }

  if (NeedsAuth()) {
    scoped_refptr<AuthChallengeInfo> auth_info;
    GetAuthChallengeInfo(&auth_info);

    // Need to check for a NULL auth_info because the server may have failed
    // to send a challenge with the 401 response.
    if (auth_info.get()) {
      request_->NotifyAuthRequired(auth_info.get());
      // Wait for SetAuth or CancelAuth to be called.
      return;
    }
  }

  has_handled_response_ = true;
  if (request_->status().is_success()) {
    DCHECK(!source_stream_);
    source_stream_ = SetUpSourceStream();

    if (!source_stream_) {
      OnDone(URLRequestStatus(URLRequestStatus::FAILED,
                              ERR_CONTENT_DECODING_INIT_FAILED),
             true);
      return;
    }
    if (source_stream_->type() == SourceStream::TYPE_NONE) {
      std::string content_length;
      request_->GetResponseHeaderByName("content-length", &content_length);
      if (!content_length.empty())
        base::StringToInt64(content_length, &expected_content_size_);
    } else {
      request_->net_log().AddEvent(
          NetLogEventType::URL_REQUEST_FILTERS_SET,
          base::Bind(&SourceStreamSetCallback,
                     base::Unretained(source_stream_.get())));
    }
  }

  request_->NotifyResponseStarted(URLRequestStatus());

  // |this| may be destroyed at this point.
}

void URLRequestJob::ConvertResultToError(int result, Error* error, int* count) {
  if (result >= 0) {
    *error = OK;
    *count = result;
  } else {
    *error = static_cast<Error>(result);
    *count = 0;
  }
}

void URLRequestJob::ReadRawDataComplete(int result) {
  DCHECK(request_->status().is_io_pending());
  DCHECK_NE(ERR_IO_PENDING, result);

  // TODO(cbentzel): Remove ScopedTracker below once crbug.com/475755 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "475755 URLRequestJob::RawReadCompleted"));

  // The headers should be complete before reads complete
  DCHECK(has_handled_response_);

  GatherRawReadStats(result);

  // Notify SourceStream.
  DCHECK(!read_raw_callback_.is_null());

  base::ResetAndReturn(&read_raw_callback_).Run(result);
  // |this| may be destroyed at this point.
}

void URLRequestJob::NotifyStartError(const URLRequestStatus &status) {
  DCHECK(!has_handled_response_);
  DCHECK(request_->status().is_io_pending());

  has_handled_response_ = true;
  // There may be relevant information in the response info even in the
  // error case.
  GetResponseInfo(&request_->response_info_);

  MaybeNotifyNetworkBytes();

  request_->NotifyResponseStarted(status);
  // |this| may have been deleted here.
}

void URLRequestJob::OnDone(const URLRequestStatus& status, bool notify_done) {
  DCHECK(!done_) << "Job sending done notification twice";
  if (done_)
    return;
  done_ = true;

  // Unless there was an error, we should have at least tried to handle
  // the response before getting here.
  DCHECK(has_handled_response_ || !status.is_success());

  request_->set_is_pending(false);
  // With async IO, it's quite possible to have a few outstanding
  // requests.  We could receive a request to Cancel, followed shortly
  // by a successful IO.  For tracking the status(), once there is
  // an error, we do not change the status back to success.  To
  // enforce this, only set the status if the job is so far
  // successful.
  if (request_->status().is_success()) {
    if (status.status() == URLRequestStatus::FAILED)
      request_->net_log().AddEventWithNetErrorCode(NetLogEventType::FAILED,
                                                   status.error());
    request_->set_status(status);
  }

  MaybeNotifyNetworkBytes();

  if (notify_done) {
    // Complete this notification later.  This prevents us from re-entering the
    // delegate if we're done because of a synchronous call.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&URLRequestJob::NotifyDone, weak_factory_.GetWeakPtr()));
  }
}

void URLRequestJob::NotifyDone() {
  // Check if we should notify the URLRequest that we're done because of an
  // error.
  if (!request_->status().is_success()) {
    // We report the error differently depending on whether we've called
    // OnResponseStarted yet.
    if (has_handled_response_) {
      // We signal the error by calling OnReadComplete with a bytes_read of -1.
      request_->NotifyReadCompleted(-1);
    } else {
      has_handled_response_ = true;
      request_->NotifyResponseStarted(URLRequestStatus());
    }
  }
}

void URLRequestJob::NotifyCanceled() {
  if (!done_) {
    OnDone(URLRequestStatus(URLRequestStatus::CANCELED, ERR_ABORTED), true);
  }
}

void URLRequestJob::NotifyRestartRequired() {
  DCHECK(!has_handled_response_);
  if (GetStatus().status() != URLRequestStatus::CANCELED)
    request_->Restart();
}

void URLRequestJob::OnCallToDelegate() {
  request_->OnCallToDelegate();
}

void URLRequestJob::OnCallToDelegateComplete() {
  request_->OnCallToDelegateComplete();
}

int URLRequestJob::ReadRawData(IOBuffer* buf, int buf_size) {
  return 0;
}

void URLRequestJob::DoneReading() {
  // Do nothing.
}

void URLRequestJob::DoneReadingRedirectResponse() {
}

std::unique_ptr<SourceStream> URLRequestJob::SetUpSourceStream() {
  return base::MakeUnique<URLRequestJobSourceStream>(this);
}

void URLRequestJob::DestroySourceStream() {
  source_stream_.reset();
}

const URLRequestStatus URLRequestJob::GetStatus() {
  return request_->status();
}

void URLRequestJob::SetProxyServer(const ProxyServer& proxy_server) {
  request_->proxy_server_ = proxy_server;
}

void URLRequestJob::SourceStreamReadComplete(bool synchronous, int result) {
  DCHECK_NE(ERR_IO_PENDING, result);

  if (result > 0 && request()->net_log().IsCapturing()) {
    request()->net_log().AddByteTransferEvent(
        NetLogEventType::URL_REQUEST_JOB_FILTERED_BYTES_READ, result,
        pending_read_buffer_->data());
  }
  pending_read_buffer_ = nullptr;

  if (result < 0) {
    OnDone(URLRequestStatus::FromError(result), !synchronous);
    return;
  }

  if (result > 0) {
    postfilter_bytes_read_ += result;
  } else {
    DCHECK_EQ(0, result);
    DoneReading();
    // In the synchronous case, the caller will notify the URLRequest of
    // completion. In the async case, the NotifyReadCompleted call will.
    // TODO(mmenke): Can this be combined with the error case?
    OnDone(URLRequestStatus(), false);
  }

  if (!synchronous)
    request_->NotifyReadCompleted(result);
}

int URLRequestJob::ReadRawDataHelper(IOBuffer* buf,
                                     int buf_size,
                                     const CompletionCallback& callback) {
  DCHECK(!raw_read_buffer_);

  // Keep a pointer to the read buffer, so URLRequestJob::GatherRawReadStats()
  // has access to it to log stats.
  raw_read_buffer_ = buf;

  // TODO(xunjieli): Make ReadRawData take in a callback rather than requiring
  // subclass to call ReadRawDataComplete upon asynchronous completion.
  int result = ReadRawData(buf, buf_size);

  if (result != ERR_IO_PENDING) {
    // If the read completes synchronously, either success or failure, invoke
    // GatherRawReadStats so we can account for the completed read.
    GatherRawReadStats(result);
  } else {
    read_raw_callback_ = callback;
  }
  return result;
}

int URLRequestJob::CanFollowRedirect(const GURL& new_url) {
  if (request_->redirect_limit_ <= 0) {
    DVLOG(1) << "disallowing redirect: exceeds limit";
    return ERR_TOO_MANY_REDIRECTS;
  }

  if (!new_url.is_valid())
    return ERR_INVALID_REDIRECT;

  if (!IsSafeRedirect(new_url)) {
    DVLOG(1) << "disallowing redirect: unsafe protocol";
    return ERR_UNSAFE_REDIRECT;
  }

  return OK;
}

void URLRequestJob::FollowRedirect(const RedirectInfo& redirect_info) {
  request_->Redirect(redirect_info);
}

void URLRequestJob::GatherRawReadStats(int bytes_read) {
  DCHECK(raw_read_buffer_ || bytes_read == 0);
  DCHECK_NE(ERR_IO_PENDING, bytes_read);

  if (bytes_read > 0) {
    // If there is a filter, bytes will be logged after the filter is applied.
    if (source_stream_->type() != SourceStream::TYPE_NONE &&
        request()->net_log().IsCapturing()) {
      request()->net_log().AddByteTransferEvent(
          NetLogEventType::URL_REQUEST_JOB_BYTES_READ, bytes_read,
          raw_read_buffer_->data());
    }
    RecordBytesRead(bytes_read);
  }
  raw_read_buffer_ = nullptr;
}

void URLRequestJob::RecordBytesRead(int bytes_read) {
  DCHECK_GT(bytes_read, 0);
  prefilter_bytes_read_ += base::checked_cast<size_t>(bytes_read);

  // On first read, notify NetworkQualityEstimator that response headers have
  // been received.
  // TODO(tbansal): Move this to url_request_http_job.cc. This may catch
  // Service Worker jobs twice.
  // If prefilter_bytes_read_ is equal to bytes_read, it indicates this is the
  // first raw read of the response body. This is used as the signal that
  // response headers have been received.
  if (request_->context()->network_quality_estimator() &&
      prefilter_bytes_read() == bytes_read) {
    request_->context()->network_quality_estimator()->NotifyHeadersReceived(
        *request_);
  }

  DVLOG(2) << __FUNCTION__ << "() "
           << "\"" << request_->url().spec() << "\""
           << " pre bytes read = " << bytes_read
           << " pre total = " << prefilter_bytes_read()
           << " post total = " << postfilter_bytes_read();
  UpdatePacketReadTimes();  // Facilitate stats recording if it is active.

  // Notify observers if any additional network usage has occurred. Note that
  // the number of received bytes over the network sent by this notification
  // could be vastly different from |bytes_read|, such as when a large chunk of
  // network bytes is received before multiple smaller raw reads are performed
  // on it.
  MaybeNotifyNetworkBytes();
}

void URLRequestJob::UpdatePacketReadTimes() {
}

RedirectInfo URLRequestJob::ComputeRedirectInfo(const GURL& location,
                                                int http_status_code) {
  const GURL& url = request_->url();

  RedirectInfo redirect_info;

  redirect_info.status_code = http_status_code;

  // The request method may change, depending on the status code.
  redirect_info.new_method =
      ComputeMethodForRedirect(request_->method(), http_status_code);

  // Move the reference fragment of the old location to the new one if the
  // new one has none. This duplicates mozilla's behavior.
  if (url.is_valid() && url.has_ref() && !location.has_ref() &&
      CopyFragmentOnRedirect(location)) {
    GURL::Replacements replacements;
    // Reference the |ref| directly out of the original URL to avoid a
    // malloc.
    replacements.SetRef(url.spec().data(),
                        url.parsed_for_possibly_invalid_spec().ref);
    redirect_info.new_url = location.ReplaceComponents(replacements);
  } else {
    redirect_info.new_url = location;
  }

  // Update the first-party URL if appropriate.
  if (request_->first_party_url_policy() ==
          URLRequest::UPDATE_FIRST_PARTY_URL_ON_REDIRECT) {
    redirect_info.new_first_party_for_cookies = redirect_info.new_url;
  } else {
    redirect_info.new_first_party_for_cookies =
        request_->first_party_for_cookies();
  }

  redirect_info.new_referrer_policy =
      ProcessReferrerPolicyHeaderOnRedirect(request_);

  // Alter the referrer if redirecting cross-origin (especially HTTP->HTTPS).
  redirect_info.new_referrer =
      ComputeReferrerForPolicy(redirect_info.new_referrer_policy,
                               GURL(request_->referrer()),
                               redirect_info.new_url)
          .spec();

  std::string include_referer;
  request_->GetResponseHeaderByName("include-referred-token-binding-id",
                                    &include_referer);
  include_referer = base::ToLowerASCII(include_referer);
  if (include_referer == "true" &&
      request_->ssl_info().token_binding_negotiated) {
    redirect_info.referred_token_binding_host = url.host();
  }

  return redirect_info;
}

void URLRequestJob::MaybeNotifyNetworkBytes() {
  if (!network_delegate_)
    return;

  // Report any new received bytes.
  int64_t total_received_bytes = GetTotalReceivedBytes();
  DCHECK_GE(total_received_bytes, last_notified_total_received_bytes_);
  if (total_received_bytes > last_notified_total_received_bytes_) {
    network_delegate_->NotifyNetworkBytesReceived(
        request_, total_received_bytes - last_notified_total_received_bytes_);
  }
  last_notified_total_received_bytes_ = total_received_bytes;

  // Report any new sent bytes.
  int64_t total_sent_bytes = GetTotalSentBytes();
  DCHECK_GE(total_sent_bytes, last_notified_total_sent_bytes_);
  if (total_sent_bytes > last_notified_total_sent_bytes_) {
    network_delegate_->NotifyNetworkBytesSent(
        request_, total_sent_bytes - last_notified_total_sent_bytes_);
  }
  last_notified_total_sent_bytes_ = total_sent_bytes;
}

}  // namespace net
