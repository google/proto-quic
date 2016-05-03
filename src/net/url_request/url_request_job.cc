// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_job.h"

#include <utility>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/power_monitor/power_monitor.h"
#include "base/profiler/scoped_tracker.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/base/auth.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate.h"
#include "net/filter/filter.h"
#include "net/http/http_response_headers.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/url_request/url_request_context.h"

namespace net {

namespace {

// Callback for TYPE_URL_REQUEST_FILTERS_SET net-internals event.
std::unique_ptr<base::Value> FiltersSetCallback(
    Filter* filter,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> event_params(
      new base::DictionaryValue());
  event_params->SetString("filters", filter->OrderedFilterList());
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

}  // namespace

URLRequestJob::URLRequestJob(URLRequest* request,
                             NetworkDelegate* network_delegate)
    : request_(request),
      done_(false),
      prefilter_bytes_read_(0),
      postfilter_bytes_read_(0),
      filter_needs_more_output_space_(false),
      filtered_read_buffer_len_(0),
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

// This function calls ReadRawData to get stream data. If a filter exists, it
// passes the data to the attached filter. It then returns the output from
// filter back to the caller.
bool URLRequestJob::Read(IOBuffer* buf, int buf_size, int *bytes_read) {
  DCHECK_LT(buf_size, 1000000);  // Sanity check.
  DCHECK(buf);
  DCHECK(bytes_read);
  DCHECK(filtered_read_buffer_.get() == NULL);
  DCHECK_EQ(0, filtered_read_buffer_len_);

  Error error = OK;
  *bytes_read = 0;

  // Skip Filter if not present.
  if (!filter_) {
    error = ReadRawDataHelper(buf, buf_size, bytes_read);
  } else {
    // Save the caller's buffers while we do IO
    // in the filter's buffers.
    filtered_read_buffer_ = buf;
    filtered_read_buffer_len_ = buf_size;

    error = ReadFilteredData(bytes_read);

    // Synchronous EOF from the filter.
    if (error == OK && *bytes_read == 0)
      DoneReading();
  }

  if (error == OK) {
    // If URLRequestJob read zero bytes, the job is at EOF.
    if (*bytes_read == 0)
      NotifyDone(URLRequestStatus());
  } else if (error == ERR_IO_PENDING) {
    SetStatus(URLRequestStatus::FromError(ERR_IO_PENDING));
  } else {
    NotifyDone(URLRequestStatus::FromError(error));
    *bytes_read = -1;
  }
  return error == OK;
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

UploadProgress URLRequestJob::GetUploadProgress() const {
  return UploadProgress();
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

bool URLRequestJob::GetResponseCookies(std::vector<std::string>* cookies) {
  return false;
}

void URLRequestJob::PopulateNetErrorDetails(NetErrorDetails* details) const {
  return;
}

Filter* URLRequestJob::SetupFilter() const {
  return NULL;
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

void URLRequestJob::ContinueWithCertificate(X509Certificate* client_cert,
                                            SSLPrivateKey* client_private_key) {
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
  DCHECK_NE(-1, deferred_redirect_info_.status_code);

  // NOTE: deferred_redirect_info_ may be invalid, and attempting to follow it
  // will fail inside FollowRedirect.  The DCHECK above asserts that we called
  // OnReceivedRedirect.

  // It is also possible that FollowRedirect will delete |this|, so not safe to
  // pass along reference to |deferred_redirect_info_|.

  RedirectInfo redirect_info = deferred_redirect_info_;
  deferred_redirect_info_ = RedirectInfo();
  FollowRedirect(redirect_info);
}

void URLRequestJob::ResumeNetworkStart() {
  // This should only be called for HTTP Jobs, and implemented in the derived
  // class.
  NOTREACHED();
}

bool URLRequestJob::GetMimeType(std::string* mime_type) const {
  return false;
}

int URLRequestJob::GetResponseCode() const {
  return -1;
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
GURL URLRequestJob::ComputeReferrerForRedirect(
    URLRequest::ReferrerPolicy policy,
    const std::string& referrer,
    const GURL& redirect_destination) {
  GURL original_referrer(referrer);
  bool secure_referrer_but_insecure_destination =
      original_referrer.SchemeIsCryptographic() &&
      !redirect_destination.SchemeIsCryptographic();
  bool same_origin =
      original_referrer.GetOrigin() == redirect_destination.GetOrigin();
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
        return original_referrer.GetOrigin();
      }

    case URLRequest::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN:
      return same_origin ? original_referrer : original_referrer.GetOrigin();

    case URLRequest::NEVER_CLEAR_REFERRER:
      return original_referrer;
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

void URLRequestJob::NotifyBeforeNetworkStart(bool* defer) {
  request_->NotifyBeforeNetworkStart(defer);
}

void URLRequestJob::NotifyHeadersComplete() {
  if (has_handled_response_)
    return;

  // The URLRequest status should still be IO_PENDING, which it was set to
  // before the URLRequestJob was started.  On error or cancellation, this
  // method should not be called.
  DCHECK(request_->status().is_io_pending());
  SetStatus(URLRequestStatus());

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
  if (request_->status().is_success())
    filter_.reset(SetupFilter());

  if (!filter_.get()) {
    std::string content_length;
    request_->GetResponseHeaderByName("content-length", &content_length);
    if (!content_length.empty())
      base::StringToInt64(content_length, &expected_content_size_);
  } else {
    request_->net_log().AddEvent(
        NetLog::TYPE_URL_REQUEST_FILTERS_SET,
        base::Bind(&FiltersSetCallback, base::Unretained(filter_.get())));
  }

  request_->NotifyResponseStarted();

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

  // TODO(cbentzel): Remove ScopedTracker below once crbug.com/475755 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "475755 URLRequestJob::RawReadCompleted"));

  // TODO(darin): Bug 1004233. Re-enable this test once all of the chrome
  // unit_tests have been fixed to not trip this.
#if 0
  DCHECK(!request_->status().is_io_pending());
#endif
  // The headers should be complete before reads complete
  DCHECK(has_handled_response_);

  Error error;
  int bytes_read;
  ConvertResultToError(result, &error, &bytes_read);

  DCHECK_NE(ERR_IO_PENDING, error);

  GatherRawReadStats(error, bytes_read);

  if (filter_.get() && error == OK) {
    // |bytes_read| being 0 indicates an EOF was received.  ReadFilteredData
    // can incorrectly return ERR_IO_PENDING when 0 bytes are passed to it, so
    // just don't call into the filter in that case.
    int filter_bytes_read = 0;
    if (bytes_read > 0) {
      // Tell the filter that it has more data.
      PushInputToFilter(bytes_read);

      // Filter the data.
      error = ReadFilteredData(&filter_bytes_read);
    }

    if (error == OK && !filter_bytes_read)
      DoneReading();

    DVLOG(1) << __FUNCTION__ << "() "
             << "\"" << request_->url().spec() << "\""
             << " pre bytes read = " << bytes_read
             << " pre total = " << prefilter_bytes_read_
             << " post total = " << postfilter_bytes_read_;
    bytes_read = filter_bytes_read;
  } else {
    DVLOG(1) << __FUNCTION__ << "() "
             << "\"" << request_->url().spec() << "\""
             << " pre bytes read = " << bytes_read
             << " pre total = " << prefilter_bytes_read_
             << " post total = " << postfilter_bytes_read_;
  }

  // Synchronize the URLRequest state machine with the URLRequestJob state
  // machine. If this read succeeded, either the request is at EOF and the
  // URLRequest state machine goes to 'finished', or it is not and the
  // URLRequest state machine goes to 'success'. If the read failed, the
  // URLRequest state machine goes directly to 'finished'.  If filtered data is
  // pending, then there's nothing to do, since the status of the request is
  // already pending.
  //
  // Update the URLRequest's status first, so that NotifyReadCompleted has an
  // accurate view of the request.
  if (error == OK && bytes_read > 0) {
    SetStatus(URLRequestStatus());
  } else if (error != ERR_IO_PENDING) {
    NotifyDone(URLRequestStatus::FromError(error));
  }

  // NotifyReadCompleted should be called after SetStatus or NotifyDone updates
  // the status.
  if (error == OK)
    request_->NotifyReadCompleted(bytes_read);

  // |this| may be destroyed at this point.
}

void URLRequestJob::NotifyStartError(const URLRequestStatus &status) {
  DCHECK(!has_handled_response_);
  DCHECK(request_->status().is_io_pending());

  has_handled_response_ = true;
  // There may be relevant information in the response info even in the
  // error case.
  GetResponseInfo(&request_->response_info_);

  SetStatus(status);
  request_->NotifyResponseStarted();
  // |this| may have been deleted here.
}

void URLRequestJob::NotifyDone(const URLRequestStatus &status) {
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
    if (status.status() == URLRequestStatus::FAILED) {
      request_->net_log().AddEventWithNetErrorCode(NetLog::TYPE_FAILED,
                                                   status.error());
    }
    request_->set_status(status);
  }

  // If the request succeeded (And wasn't cancelled) and the response code was
  // 4xx or 5xx, record whether or not the main frame was blank.  This is
  // intended to be a short-lived histogram, used to figure out how important
  // fixing http://crbug.com/331745 is.
  if (request_->status().is_success()) {
    int response_code = GetResponseCode();
    if (400 <= response_code && response_code <= 599) {
      bool page_has_content = (postfilter_bytes_read_ != 0);
      if (request_->load_flags() & net::LOAD_MAIN_FRAME) {
        UMA_HISTOGRAM_BOOLEAN("Net.ErrorResponseHasContentMainFrame",
                              page_has_content);
      } else {
        UMA_HISTOGRAM_BOOLEAN("Net.ErrorResponseHasContentNonMainFrame",
                              page_has_content);
      }
    }
  }

  MaybeNotifyNetworkBytes();

  // Complete this notification later.  This prevents us from re-entering the
  // delegate if we're done because of a synchronous call.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestJob::CompleteNotifyDone,
                            weak_factory_.GetWeakPtr()));
}

void URLRequestJob::CompleteNotifyDone() {
  // Check if we should notify the delegate that we're done because of an error.
  if (!request_->status().is_success()) {
    // We report the error differently depending on whether we've called
    // OnResponseStarted yet.
    if (has_handled_response_) {
      // We signal the error by calling OnReadComplete with a bytes_read of -1.
      request_->NotifyReadCompleted(-1);
    } else {
      has_handled_response_ = true;
      request_->NotifyResponseStarted();
    }
  }
}

void URLRequestJob::NotifyCanceled() {
  if (!done_) {
    NotifyDone(URLRequestStatus(URLRequestStatus::CANCELED, ERR_ABORTED));
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

void URLRequestJob::PushInputToFilter(int bytes_read) {
  DCHECK(filter_);
  filter_->FlushStreamBuffer(bytes_read);
}

Error URLRequestJob::ReadFilteredData(int* bytes_read) {
  DCHECK(filter_);
  DCHECK(filtered_read_buffer_.get());
  DCHECK_GT(filtered_read_buffer_len_, 0);
  DCHECK_LT(filtered_read_buffer_len_, 1000000);  // Sanity check.
  DCHECK(!raw_read_buffer_);

  *bytes_read = 0;
  Error error = ERR_FAILED;

  for (;;) {
    if (is_done())
      return OK;

    if (!filter_needs_more_output_space_ && !filter_->stream_data_len()) {
      // We don't have any raw data to work with, so read from the transaction.
      int filtered_data_read;
      error = ReadRawDataForFilter(&filtered_data_read);
      // If ReadRawDataForFilter returned some data, fall through to the case
      // below; otherwise, return early.
      if (error != OK || filtered_data_read == 0)
        return error;
      filter_->FlushStreamBuffer(filtered_data_read);
    }

    if ((filter_->stream_data_len() || filter_needs_more_output_space_) &&
        !is_done()) {
      // Get filtered data.
      int filtered_data_len = filtered_read_buffer_len_;
      int output_buffer_size = filtered_data_len;
      Filter::FilterStatus status =
          filter_->ReadData(filtered_read_buffer_->data(), &filtered_data_len);

      if (filter_needs_more_output_space_ && !filtered_data_len) {
        // filter_needs_more_output_space_ was mistaken... there are no more
        // bytes and we should have at least tried to fill up the filter's input
        // buffer. Correct the state, and try again.
        filter_needs_more_output_space_ = false;
        continue;
      }
      filter_needs_more_output_space_ =
          (filtered_data_len == output_buffer_size);

      switch (status) {
        case Filter::FILTER_DONE: {
          filter_needs_more_output_space_ = false;
          *bytes_read = filtered_data_len;
          postfilter_bytes_read_ += filtered_data_len;
          error = OK;
          break;
        }
        case Filter::FILTER_NEED_MORE_DATA: {
          // We have finished filtering all data currently in the buffer.
          // There might be some space left in the output buffer. One can
          // consider reading more data from the stream to feed the filter
          // and filling up the output buffer. This leads to more complicated
          // buffer management and data notification mechanisms.
          // We can revisit this issue if there is a real perf need.
          if (filtered_data_len > 0) {
            *bytes_read = filtered_data_len;
            postfilter_bytes_read_ += filtered_data_len;
            error = OK;
          } else {
            // Read again since we haven't received enough data yet (e.g., we
            // may not have a complete gzip header yet).
            continue;
          }
          break;
        }
        case Filter::FILTER_OK: {
          *bytes_read = filtered_data_len;
          postfilter_bytes_read_ += filtered_data_len;
          error = OK;
          break;
        }
        case Filter::FILTER_ERROR: {
          DVLOG(1) << __FUNCTION__ << "() "
                   << "\"" << request_->url().spec() << "\""
                   << " Filter Error";
          filter_needs_more_output_space_ = false;
          error = ERR_CONTENT_DECODING_FAILED;
          UMA_HISTOGRAM_ENUMERATION("Net.ContentDecodingFailed.FilterType",
                                    filter_->type(), Filter::FILTER_TYPE_MAX);
          break;
        }
        default: {
          NOTREACHED();
          filter_needs_more_output_space_ = false;
          error = ERR_FAILED;
          break;
        }
      }

      // If logging all bytes is enabled, log the filtered bytes read.
      if (error == OK && filtered_data_len > 0 &&
          request()->net_log().IsCapturing()) {
        request()->net_log().AddByteTransferEvent(
            NetLog::TYPE_URL_REQUEST_JOB_FILTERED_BYTES_READ, filtered_data_len,
            filtered_read_buffer_->data());
      }
    } else {
      // we are done, or there is no data left.
      error = OK;
    }
    break;
  }

  if (error == OK) {
    // When we successfully finished a read, we no longer need to save the
    // caller's buffers. Release our reference.
    filtered_read_buffer_ = NULL;
    filtered_read_buffer_len_ = 0;
  }
  return error;
}

void URLRequestJob::DestroyFilters() {
  filter_.reset();
}

const URLRequestStatus URLRequestJob::GetStatus() {
  return request_->status();
}

void URLRequestJob::SetStatus(const URLRequestStatus &status) {
  // An error status should never be replaced by a non-error status by a
  // URLRequestJob.  URLRequest has some retry paths, but it resets the status
  // itself, if needed.
  DCHECK(request_->status().is_io_pending() ||
         request_->status().is_success() ||
         (!status.is_success() && !status.is_io_pending()));
  request_->set_status(status);
}

void URLRequestJob::SetProxyServer(const HostPortPair& proxy_server) {
  request_->proxy_server_ = proxy_server;
}

Error URLRequestJob::ReadRawDataForFilter(int* bytes_read) {
  Error error = ERR_FAILED;
  DCHECK(bytes_read);
  DCHECK(filter_.get());

  *bytes_read = 0;

  // Get more pre-filtered data if needed.
  // TODO(mbelshe): is it possible that the filter needs *MORE* data
  //    when there is some data already in the buffer?
  if (!filter_->stream_data_len() && !is_done()) {
    IOBuffer* stream_buffer = filter_->stream_buffer();
    int stream_buffer_size = filter_->stream_buffer_size();
    error = ReadRawDataHelper(stream_buffer, stream_buffer_size, bytes_read);
  }
  return error;
}

Error URLRequestJob::ReadRawDataHelper(IOBuffer* buf,
                                       int buf_size,
                                       int* bytes_read) {
  DCHECK(!raw_read_buffer_);

  // Keep a pointer to the read buffer, so we have access to it in
  // GatherRawReadStats() in the event that the read completes asynchronously.
  raw_read_buffer_ = buf;
  Error error;
  ConvertResultToError(ReadRawData(buf, buf_size), &error, bytes_read);

  if (error != ERR_IO_PENDING) {
    // If the read completes synchronously, either success or failure, invoke
    // GatherRawReadStats so we can account for the completed read.
    GatherRawReadStats(error, *bytes_read);
  }
  return error;
}

void URLRequestJob::FollowRedirect(const RedirectInfo& redirect_info) {
  int rv = request_->Redirect(redirect_info);
  if (rv != OK)
    NotifyDone(URLRequestStatus(URLRequestStatus::FAILED, rv));
}

void URLRequestJob::GatherRawReadStats(Error error, int bytes_read) {
  DCHECK(raw_read_buffer_ || bytes_read == 0);
  DCHECK_NE(ERR_IO_PENDING, error);

  if (error != OK) {
    raw_read_buffer_ = nullptr;
    return;
  }
  // If |filter_| is non-NULL, bytes will be logged after it is applied
  // instead.
  if (!filter_.get() && bytes_read > 0 && request()->net_log().IsCapturing()) {
    request()->net_log().AddByteTransferEvent(
        NetLog::TYPE_URL_REQUEST_JOB_BYTES_READ, bytes_read,
        raw_read_buffer_->data());
  }

  if (bytes_read > 0) {
    RecordBytesRead(bytes_read);
  }
  raw_read_buffer_ = nullptr;
}

void URLRequestJob::RecordBytesRead(int bytes_read) {
  DCHECK_GT(bytes_read, 0);
  prefilter_bytes_read_ += bytes_read;

  // On first read, notify NetworkQualityEstimator that response headers have
  // been received.
  // TODO(tbansal): Move this to url_request_http_job.cc. This may catch
  // Service Worker jobs twice.
  // If prefilter_bytes_read_ is equal to bytes_read, it indicates this is the
  // first raw read of the response body. This is used as the signal that
  // response headers have been received.
  if (request_->context()->network_quality_estimator() &&
      prefilter_bytes_read_ == bytes_read) {
    request_->context()->network_quality_estimator()->NotifyHeadersReceived(
        *request_);
  }

  if (!filter_.get())
    postfilter_bytes_read_ += bytes_read;
  DVLOG(2) << __FUNCTION__ << "() "
           << "\"" << request_->url().spec() << "\""
           << " pre bytes read = " << bytes_read
           << " pre total = " << prefilter_bytes_read_
           << " post total = " << postfilter_bytes_read_;
  UpdatePacketReadTimes();  // Facilitate stats recording if it is active.

  // Notify observers if any additional network usage has occurred. Note that
  // the number of received bytes over the network sent by this notification
  // could be vastly different from |bytes_read|, such as when a large chunk of
  // network bytes is received before multiple smaller raw reads are performed
  // on it.
  MaybeNotifyNetworkBytes();
}

bool URLRequestJob::FilterHasData() {
    return filter_.get() && filter_->stream_data_len();
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

  // Alter the referrer if redirecting cross-origin (especially HTTP->HTTPS).
  redirect_info.new_referrer =
      ComputeReferrerForRedirect(request_->referrer_policy(),
                                 request_->referrer(),
                                 redirect_info.new_url).spec();

  std::string include_referer;
  request_->GetResponseHeaderByName("include-referer-token-binding-id",
                                    &include_referer);
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
