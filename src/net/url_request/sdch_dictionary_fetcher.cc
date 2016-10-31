// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/sdch_dictionary_fetcher.h"

#include <stdint.h>
#include <queue>
#include <set>

#include "base/auto_reset.h"
#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/sdch_net_log_params.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_status.h"
#include "net/url_request/url_request_throttler_manager.h"

namespace net {

namespace {

const int kBufferSize = 4096;

// Map the bytes_read result from a read attempt and a URLRequest's
// status into a single net return value.
int GetReadResult(int rv, const URLRequest* request) {
  DCHECK_NE(ERR_IO_PENDING, rv);

  if (rv < 0) {
    rv = ERR_FAILED;
    request->net_log().AddEventWithNetErrorCode(
        NetLogEventType::SDCH_DICTIONARY_FETCH_IMPLIED_ERROR, rv);
  }

  return rv;
}

struct FetchInfo {
  FetchInfo(const GURL& url,
            bool cache_only,
            const SdchDictionaryFetcher::OnDictionaryFetchedCallback& callback)
      : url(url), cache_only(cache_only), callback(callback) {}
  FetchInfo() {}

  GURL url;
  bool cache_only;
  SdchDictionaryFetcher::OnDictionaryFetchedCallback callback;
};

}  // namespace

// A UniqueFetchQueue is used to queue outgoing requests, which are either cache
// requests or network requests (which *may* still be served from cache).
// The UniqueFetchQueue enforces that a URL can only be queued for network fetch
// at most once. Calling Clear() resets UniqueFetchQueue's memory of which URLs
// have been queued.
class SdchDictionaryFetcher::UniqueFetchQueue {
 public:
  UniqueFetchQueue();
  ~UniqueFetchQueue();

  bool Push(const FetchInfo& info);
  bool Pop(FetchInfo* info);
  bool IsEmpty() const;
  void Clear();

 private:
  std::queue<FetchInfo> queue_;
  std::set<GURL> ever_network_queued_;

  DISALLOW_COPY_AND_ASSIGN(UniqueFetchQueue);
};

SdchDictionaryFetcher::UniqueFetchQueue::UniqueFetchQueue() {}
SdchDictionaryFetcher::UniqueFetchQueue::~UniqueFetchQueue() {}

bool SdchDictionaryFetcher::UniqueFetchQueue::Push(const FetchInfo& info) {
  if (ever_network_queued_.count(info.url) != 0)
    return false;
  if (!info.cache_only)
    ever_network_queued_.insert(info.url);
  queue_.push(info);
  return true;
}

bool SdchDictionaryFetcher::UniqueFetchQueue::Pop(FetchInfo* info) {
  if (IsEmpty())
    return false;
  *info = queue_.front();
  queue_.pop();
  return true;
}

bool SdchDictionaryFetcher::UniqueFetchQueue::IsEmpty() const {
  return queue_.empty();
}

void SdchDictionaryFetcher::UniqueFetchQueue::Clear() {
  ever_network_queued_.clear();
  while (!queue_.empty())
    queue_.pop();
}

SdchDictionaryFetcher::SdchDictionaryFetcher(URLRequestContext* context)
    : next_state_(STATE_NONE),
      in_loop_(false),
      fetch_queue_(new UniqueFetchQueue()),
      context_(context) {
  DCHECK(CalledOnValidThread());
  DCHECK(context);
}

SdchDictionaryFetcher::~SdchDictionaryFetcher() {
}

bool SdchDictionaryFetcher::Schedule(
    const GURL& dictionary_url,
    const OnDictionaryFetchedCallback& callback) {
  return ScheduleInternal(dictionary_url, false, callback);
}

bool SdchDictionaryFetcher::ScheduleReload(
    const GURL& dictionary_url,
    const OnDictionaryFetchedCallback& callback) {
  return ScheduleInternal(dictionary_url, true, callback);
}

void SdchDictionaryFetcher::Cancel() {
  DCHECK(CalledOnValidThread());

  ResetRequest();
  next_state_ = STATE_NONE;

  fetch_queue_->Clear();
}

void SdchDictionaryFetcher::OnReceivedRedirect(
    URLRequest* request,
    const RedirectInfo& redirect_info,
    bool* defer_redirect) {
  DCHECK_EQ(next_state_, STATE_SEND_REQUEST_PENDING);

  next_state_ = STATE_RECEIVED_REDIRECT;

  DoLoop(OK);
}

void SdchDictionaryFetcher::OnResponseStarted(URLRequest* request,
                                              int net_error) {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(request, current_request_.get());
  DCHECK_EQ(next_state_, STATE_SEND_REQUEST_PENDING);
  DCHECK(!in_loop_);
  DCHECK_NE(ERR_IO_PENDING, net_error);

  // Confirm that the response isn't a stale read from the cache (as
  // may happen in the reload case).  If the response was not retrieved over
  // HTTP, it is presumed to be fresh.
  HttpResponseHeaders* response_headers = request->response_headers();
  if (net_error == OK && response_headers) {
    ValidationType validation_type = response_headers->RequiresValidation(
        request->response_info().request_time,
        request->response_info().response_time, base::Time::Now());
    // TODO(rdsmith): Maybe handle VALIDATION_ASYNCHRONOUS by queueing
    // a non-reload request for the dictionary.
    if (validation_type != VALIDATION_NONE)
      net_error = ERR_FAILED;
  }

  DoLoop(net_error);
}

void SdchDictionaryFetcher::OnReadCompleted(URLRequest* request,
                                            int bytes_read) {
  DCHECK(CalledOnValidThread());
  DCHECK_EQ(request, current_request_.get());
  DCHECK_EQ(next_state_, STATE_READ_BODY_COMPLETE);
  DCHECK(!in_loop_);
  DCHECK_NE(ERR_IO_PENDING, bytes_read);

  DoLoop(GetReadResult(bytes_read, current_request_.get()));
}

bool SdchDictionaryFetcher::ScheduleInternal(
    const GURL& dictionary_url,
    bool reload,
    const OnDictionaryFetchedCallback& callback) {
  DCHECK(CalledOnValidThread());

  // If Push() fails, |dictionary_url| has already been fetched or scheduled to
  // be fetched.
  if (!fetch_queue_->Push(FetchInfo(dictionary_url, reload, callback))) {
    // TODO(rdsmith): Log this error to the net log.  In the case of a
    // normal fetch, this can be through the URLRequest
    // initiating this fetch (once the URLRequest is passed to the fetcher);
    // in the case of a reload, it's more complicated.
    SdchManager::SdchErrorRecovery(
        SDCH_DICTIONARY_PREVIOUSLY_SCHEDULED_TO_DOWNLOAD);
    return false;
  }

  // If the loop is already processing, it'll pick up the above in the
  // normal course of events.
  if (next_state_ != STATE_NONE)
    return true;

  next_state_ = STATE_SEND_REQUEST;

  // There are no callbacks to user code from the dictionary fetcher,
  // and Schedule() is only called from user code, so this call to DoLoop()
  // does not require an |if (in_loop_) return;| guard.
  DoLoop(OK);
  return true;
}

void SdchDictionaryFetcher::ResetRequest() {
  current_request_.reset();
  buffer_ = nullptr;
  current_callback_.Reset();
  dictionary_.reset();
  return;
}

int SdchDictionaryFetcher::DoLoop(int rv) {
  DCHECK(!in_loop_);
  base::AutoReset<bool> auto_reset_in_loop(&in_loop_, true);

  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_SEND_REQUEST:
        rv = DoSendRequest(rv);
        break;
      case STATE_RECEIVED_REDIRECT:
        rv = DoReceivedRedirect(rv);
        break;
      case STATE_SEND_REQUEST_PENDING:
        rv = DoSendRequestPending(rv);
        break;
      case STATE_READ_BODY:
        rv = DoReadBody(rv);
        break;
      case STATE_READ_BODY_COMPLETE:
        rv = DoReadBodyComplete(rv);
        break;
      case STATE_REQUEST_COMPLETE:
        rv = DoCompleteRequest(rv);
        break;
      case STATE_NONE:
        NOTREACHED();
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

int SdchDictionaryFetcher::DoSendRequest(int rv) {
  DCHECK(CalledOnValidThread());

  // |rv| is ignored, as the result from the previous request doesn't
  // affect the next request.

  if (fetch_queue_->IsEmpty() || current_request_.get()) {
    next_state_ = STATE_NONE;
    return OK;
  }

  next_state_ = STATE_SEND_REQUEST_PENDING;

  FetchInfo info;
  bool success = fetch_queue_->Pop(&info);
  DCHECK(success);
  current_request_ = context_->CreateRequest(info.url, IDLE, this);
  int load_flags = LOAD_DO_NOT_SEND_COOKIES | LOAD_DO_NOT_SAVE_COOKIES;
  if (info.cache_only)
    load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  current_request_->SetLoadFlags(load_flags);

  buffer_ = new IOBuffer(kBufferSize);
  dictionary_.reset(new std::string());
  current_callback_ = info.callback;

  current_request_->Start();
  current_request_->net_log().AddEvent(NetLogEventType::SDCH_DICTIONARY_FETCH);

  return ERR_IO_PENDING;
}

int SdchDictionaryFetcher::DoReceivedRedirect(int rv) {
  // Fetching SDCH through a redirect is forbidden; it raises possible
  // security issues cross-origin, and isn't obviously useful within
  // an origin.
  ResetRequest();
  next_state_ = STATE_SEND_REQUEST;
  return ERR_UNSAFE_REDIRECT;
}

int SdchDictionaryFetcher::DoSendRequestPending(int rv) {
  DCHECK(CalledOnValidThread());

  // If there's been an error, abort the current request.
  if (rv != OK) {
    ResetRequest();
    next_state_ = STATE_SEND_REQUEST;
    return OK;
  }

  next_state_ = STATE_READ_BODY;
  return OK;
}

int SdchDictionaryFetcher::DoReadBody(int rv) {
  DCHECK(CalledOnValidThread());

  // If there's been an error, abort the current request.
  if (rv != OK) {
    ResetRequest();
    next_state_ = STATE_SEND_REQUEST;
    return OK;
  }

  next_state_ = STATE_READ_BODY_COMPLETE;
  int bytes_read = current_request_->Read(buffer_.get(), kBufferSize);
  if (bytes_read == ERR_IO_PENDING)
    return ERR_IO_PENDING;

  return GetReadResult(bytes_read, current_request_.get());
}

int SdchDictionaryFetcher::DoReadBodyComplete(int rv) {
  DCHECK(CalledOnValidThread());

  // An error; abort the current request.
  if (rv < 0) {
    ResetRequest();
    next_state_ = STATE_SEND_REQUEST;
    return OK;
  }

  DCHECK_GE(rv, 0);

  // Data; append to the dictionary and look for more data.
  if (rv > 0) {
    dictionary_->append(buffer_->data(), rv);
    next_state_ = STATE_READ_BODY;
    return OK;
  }

  // End of file; complete the request.
  next_state_ = STATE_REQUEST_COMPLETE;
  return OK;
}

int SdchDictionaryFetcher::DoCompleteRequest(int rv) {
  DCHECK(CalledOnValidThread());

  // If the dictionary was successfully fetched, add it to the manager.
  if (rv == OK) {
    current_callback_.Run(*dictionary_, current_request_->url(),
                          current_request_->net_log(),
                          current_request_->was_cached());
  }

  ResetRequest();
  next_state_ = STATE_SEND_REQUEST;
  return OK;
}

}  // namespace net
