// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Overview
//
// The main entry point is CertNetFetcherImpl. This is an implementation of
// CertNetFetcher that provides a service for fetching network requests.
//
// The interface for CertNetFetcher is synchronous, however allows
// overlapping requests. When starting a request CertNetFetcherImpl
// returns a CertNetFetcher::Request (CertNetFetcherImpl) that the
// caller can use to cancel the fetch, or wait for it to complete
// (blocking).
//
// The classes are mainly organized based on their thread affinity:
//
// ---------------
// Lives on caller thread
// ---------------
//
// CertNetFetcherImpl (implements CertNetFetcher)
//   * Main entry point
//   * Provides a service to start/cancel/wait for URL fetches
//   * Returns callers a CertNetFetcher::Request as a handle
//   * Requests can run in parallel, however will block the current thread when
//     reading results.
//   * Posts tasks to network thread to coordinate actual work
//
// CertNetFetcherRequestImpl (implements CertNetFetcher::Request)
//   * Wrapper for cancelling events, or waiting for a request to complete
//   * Waits on a WaitableEvent to complete requests.
//
// ---------------
// Straddles caller thread and network thread
// ---------------
//
// CertNetFetcherCore
//   * Reference-counted bridge between CertNetFetcherImpl and the dependencies
//     on network thread.
//   * Small wrapper to holds the state that is conceptually owned by
//     CertNetFetcherImpl, but belongs on the network thread.
//
// RequestCore
//   * Reference-counted bridge between CertNetFetcherRequestImpl and the
//     dependencies on the network thread
//   * Holds the result of the request, a WaitableEvent for signaling
//     completion, and pointers for canceling work on network thread.
//
// ---------------
// Lives on network thread
// ---------------
//
// AsyncCertNetFetcherImpl
//   * Asyncronous manager for outstanding requests. Handles de-duplication,
//     timeouts, and actual integration with network stack. This is where the
//     majority of the logic lives.
//   * Signals completion of requests through RequestCore's WaitableEvent.
//   * Attaches requests to Jobs for the purpose of de-duplication

#include "net/cert_net/cert_net_fetcher_impl.h"

#include <tuple>
#include <utility>

#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/safe_math.h"
#include "base/synchronization/waitable_event.h"
#include "base/timer/timer.h"
#include "net/base/load_flags.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_getter.h"

// TODO(eroman): Add support for POST parameters.
// TODO(eroman): Add controls for bypassing the cache.
// TODO(eroman): Add a maximum number of in-flight jobs/requests.
// TODO(eroman): Add NetLog integration.

namespace net {

namespace {

// The size of the buffer used for reading the response body of the URLRequest.
const int kReadBufferSizeInBytes = 4096;

// The maximum size in bytes for the response body when fetching a CRL.
const int kMaxResponseSizeInBytesForCrl = 5 * 1024 * 1024;

// The maximum size in bytes for the response body when fetching an AIA URL
// (caIssuers/OCSP).
const int kMaxResponseSizeInBytesForAia = 64 * 1024;

// The default timeout in seconds for fetch requests.
const int kTimeoutSeconds = 15;

class RequestCore;
struct RequestParams;
class Job;

struct JobToRequestParamsComparator;

struct JobComparator {
  bool operator()(const Job* job1, const Job* job2) const;
};

// Would be a set<unique_ptr> but extraction of owned objects from a set of
// owned types doesn't come until C++17.
using JobSet = std::map<Job*, std::unique_ptr<Job>, JobComparator>;

// AsyncCertNetFetcherImpl manages URLRequests in an async fashion on the
// URLRequestContexts's task runner thread.
//
//  * Schedules
//  * De-duplicates requests
//  * Handles timeouts
class AsyncCertNetFetcherImpl {
 public:
  // Initializes AsyncCertNetFetcherImpl using the specified URLRequestContext
  // for issuing requests. |context| must remain valid for the entire
  // lifetime of the AsyncCertNetFetcherImpl.
  explicit AsyncCertNetFetcherImpl(URLRequestContext* context);

  // Deletion implicitly cancels any outstanding requests.
  ~AsyncCertNetFetcherImpl();

  // Starts an asynchronous request to fetch the given URL. On completion
  // |callback| will be invoked.
  //
  // Completion of the request will never occur synchronously. In other words it
  // is guaranteed that |callback| will only be invoked once the Fetch*() method
  // has returned.
  void Fetch(std::unique_ptr<RequestParams> request_params,
             RequestCore* request);

 private:
  friend class Job;

  // Finds a job with a matching RequestPararms or returns nullptr if there was
  // no match.
  Job* FindJob(const RequestParams& params);

  // Removes |job| from the in progress jobs and transfers ownership to the
  // caller.
  std::unique_ptr<Job> RemoveJob(Job* job);

  // The in-progress jobs. This set does not contain the job which is actively
  // invoking callbacks (OnJobCompleted).
  JobSet jobs_;

  // Not owned. |context_| must outlive the AsyncCertNetFetcherImpl.
  URLRequestContext* context_ = nullptr;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(AsyncCertNetFetcherImpl);
};

// Policy for which URLs are allowed to be fetched. This is called both for the
// initial URL and for each redirect. Returns OK on success or a net error
// code on failure.
Error CanFetchUrl(const GURL& url) {
  if (!url.SchemeIs("http"))
    return ERR_DISALLOWED_URL_SCHEME;
  return OK;
}

base::TimeDelta GetTimeout(int timeout_milliseconds) {
  if (timeout_milliseconds == CertNetFetcher::DEFAULT)
    return base::TimeDelta::FromSeconds(kTimeoutSeconds);
  return base::TimeDelta::FromMilliseconds(timeout_milliseconds);
}

size_t GetMaxResponseBytes(int max_response_bytes,
                           size_t default_max_response_bytes) {
  if (max_response_bytes == CertNetFetcher::DEFAULT)
    return default_max_response_bytes;

  // Ensure that the specified limit is not negative, and cannot result in an
  // overflow while reading.
  base::CheckedNumeric<size_t> check(max_response_bytes);
  check += kReadBufferSizeInBytes;
  DCHECK(check.IsValid());

  return max_response_bytes;
}

enum HttpMethod {
  HTTP_METHOD_GET,
  HTTP_METHOD_POST,
};

// RequestCore tracks an outstanding call to Fetch(). It is
// reference-counted for ease of sharing between threads.
class RequestCore : public base::RefCountedThreadSafe<RequestCore> {
 public:
  explicit RequestCore(scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : completion_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                          base::WaitableEvent::InitialState::NOT_SIGNALED),
        task_runner_(std::move(task_runner)) {}

  void AttachedToJob(Job* job) {
    DCHECK(task_runner_->RunsTasksOnCurrentThread());
    DCHECK(!job_);
    job_ = job;
  }

  void OnJobCompleted(Job* job,
                      Error error,
                      const std::vector<uint8_t>& response_body) {
    DCHECK(task_runner_->RunsTasksOnCurrentThread());

    DCHECK_EQ(job_, job);
    job_ = nullptr;

    error_ = error;
    bytes_ = response_body;
    completion_event_.Signal();
  }

  // Can be called from any thread.
  void Cancel();

  // Should only be called once.
  void WaitForResult(Error* error, std::vector<uint8_t>* bytes) {
    DCHECK(!task_runner_->RunsTasksOnCurrentThread());

    completion_event_.Wait();
    *bytes = std::move(bytes_);
    *error = error_;

    error_ = ERR_UNEXPECTED;
  }

 private:
  friend class base::RefCountedThreadSafe<RequestCore>;

  ~RequestCore() {
    // Requests should have been cancelled prior to destruction.
    DCHECK(!job_);
  }

  // A non-owned pointer to the job that is executing the request.
  Job* job_ = nullptr;

  // May be written to from network thread.
  Error error_;
  std::vector<uint8_t> bytes_;

  // Indicates when |error_| and |bytes_| have been written to.
  base::WaitableEvent completion_event_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(RequestCore);
};

struct RequestParams {
  RequestParams();

  bool operator<(const RequestParams& other) const;

  GURL url;
  HttpMethod http_method;
  size_t max_response_bytes;

  // If set to a value <= 0 then means "no timeout".
  base::TimeDelta timeout;

  // IMPORTANT: When adding fields to this structure, update operator<().

 private:
  DISALLOW_COPY_AND_ASSIGN(RequestParams);
};

RequestParams::RequestParams()
    : http_method(HTTP_METHOD_GET), max_response_bytes(0) {}

bool RequestParams::operator<(const RequestParams& other) const {
  return std::tie(url, http_method, max_response_bytes, timeout) <
         std::tie(other.url, other.http_method, other.max_response_bytes,
                  other.timeout);
}

// Job tracks an outstanding URLRequest as well as all of the pending requests
// for it.
class Job : public URLRequest::Delegate {
 public:
  Job(std::unique_ptr<RequestParams> request_params,
      AsyncCertNetFetcherImpl* parent);
  ~Job() override;

  const RequestParams& request_params() const { return *request_params_; }

  // Create a request and attaches it to the job. When the job completes it will
  // notify the request of completion through OnJobCompleted. Note that the Job
  // does NOT own the request.
  void AttachRequest(RequestCore* request);

  // Removes |request| from the job.
  void DetachRequest(RequestCore* request);

  // Creates and starts a URLRequest for the job. After the URLRequest has
  // completed, OnJobCompleted() will be invoked and all the registered requests
  // notified of completion.
  void StartURLRequest(URLRequestContext* context);

 private:
  // Implementation of URLRequest::Delegate
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override;
  void OnResponseStarted(URLRequest* request, int net_error) override;
  void OnReadCompleted(URLRequest* request, int bytes_read) override;

  // Clears the URLRequest and timer. Helper for doing work common to
  // cancellation and job completion.
  void Stop();

  // Reads as much data as available from |request|.
  void ReadBody(URLRequest* request);

  // Helper to copy the partial bytes read from the read IOBuffer to an
  // aggregated buffer.
  bool ConsumeBytesRead(URLRequest* request, int num_bytes);

  // Called when the URLRequest has completed (either success or failure).
  void OnUrlRequestCompleted(int net_error);

  // Called when the Job has completed. The job may finish in response to a
  // timeout, an invalid URL, or the URLRequest completing. By the time this
  // method is called, the |response_body_| variable have been assigned.
  void OnJobCompleted(Error error);

  // Cancels a request with a specified error code and calls
  // OnUrlRequestCompleted().
  void FailRequest(Error error);

  // The requests attached to this job (non-owned).
  std::vector<RequestCore*> requests_;

  // The input parameters for starting a URLRequest.
  std::unique_ptr<RequestParams> request_params_;

  // The URLRequest response information.
  std::vector<uint8_t> response_body_;

  std::unique_ptr<URLRequest> url_request_;
  scoped_refptr<IOBuffer> read_buffer_;

  // Used to timeout the job when the URLRequest takes too long. This timer is
  // also used for notifying a failure to start the URLRequest.
  base::OneShotTimer timer_;

  // Non-owned pointer to the AsyncCertNetFetcherImpl that created this job.
  AsyncCertNetFetcherImpl* parent_;

  DISALLOW_COPY_AND_ASSIGN(Job);
};

void RequestCore::Cancel() {
  if (!task_runner_->RunsTasksOnCurrentThread()) {
    task_runner_->PostTask(FROM_HERE, base::Bind(&RequestCore::Cancel, this));
    return;
  }

  if (job_) {
    auto* job = job_;
    job_ = nullptr;
    job->DetachRequest(this);
  }

  bytes_.clear();
  error_ = ERR_UNEXPECTED;
}

Job::Job(std::unique_ptr<RequestParams> request_params,
         AsyncCertNetFetcherImpl* parent)
    : request_params_(std::move(request_params)), parent_(parent) {}

Job::~Job() {
  DCHECK(requests_.empty());
  Stop();
}

void Job::AttachRequest(RequestCore* request) {
  requests_.push_back(request);
  request->AttachedToJob(this);
}

void Job::DetachRequest(RequestCore* request) {
  std::unique_ptr<Job> delete_this;

  auto it = std::find(requests_.begin(), requests_.end(), request);
  DCHECK(it != requests_.end());
  requests_.erase(it);

  // If there are no longer any requests attached to the job then
  // cancel and delete it.
  if (requests_.empty())
    delete_this = parent_->RemoveJob(this);
}

void Job::StartURLRequest(URLRequestContext* context) {
  Error error = CanFetchUrl(request_params_->url);
  if (error != OK) {
    // TODO(eroman): Don't post a task for this case.
    timer_.Start(
        FROM_HERE, base::TimeDelta(),
        base::Bind(&Job::OnJobCompleted, base::Unretained(this), error));
    return;
  }

  // Start the URLRequest.
  read_buffer_ = new IOBuffer(kReadBufferSizeInBytes);
  url_request_ =
      context->CreateRequest(request_params_->url, DEFAULT_PRIORITY, this);
  if (request_params_->http_method == HTTP_METHOD_POST)
    url_request_->set_method("POST");
  url_request_->SetLoadFlags(LOAD_DO_NOT_SAVE_COOKIES |
                             LOAD_DO_NOT_SEND_COOKIES);
  url_request_->Start();

  // Start a timer to limit how long the job runs for.
  if (request_params_->timeout > base::TimeDelta())
    timer_.Start(
        FROM_HERE, request_params_->timeout,
        base::Bind(&Job::FailRequest, base::Unretained(this), ERR_TIMED_OUT));
}

void Job::OnReceivedRedirect(URLRequest* request,
                             const RedirectInfo& redirect_info,
                             bool* defer_redirect) {
  DCHECK_EQ(url_request_.get(), request);

  // Ensure that the new URL matches the policy.
  Error error = CanFetchUrl(redirect_info.new_url);
  if (error != OK) {
    FailRequest(error);
    return;
  }
}

void Job::OnResponseStarted(URLRequest* request, int net_error) {
  DCHECK_EQ(url_request_.get(), request);
  DCHECK_NE(ERR_IO_PENDING, net_error);

  if (net_error != OK) {
    OnUrlRequestCompleted(net_error);
    return;
  }

  if (request->GetResponseCode() != 200) {
    // TODO(eroman): Use a more specific error code.
    FailRequest(ERR_FAILED);
    return;
  }

  ReadBody(request);
}

void Job::OnReadCompleted(URLRequest* request, int bytes_read) {
  DCHECK_EQ(url_request_.get(), request);
  DCHECK_NE(ERR_IO_PENDING, bytes_read);

  // Keep reading the response body.
  if (ConsumeBytesRead(request, bytes_read))
    ReadBody(request);
}

void Job::Stop() {
  timer_.Stop();
  url_request_.reset();
}

void Job::ReadBody(URLRequest* request) {
  // Read as many bytes as are available synchronously.
  int num_bytes = 0;
  while (num_bytes >= 0) {
    num_bytes = request->Read(read_buffer_.get(), kReadBufferSizeInBytes);
    if (num_bytes == ERR_IO_PENDING)
      return;
    if (!ConsumeBytesRead(request, num_bytes))
      return;
  }

  OnUrlRequestCompleted(num_bytes);
}

bool Job::ConsumeBytesRead(URLRequest* request, int num_bytes) {
  DCHECK_NE(ERR_IO_PENDING, num_bytes);
  if (num_bytes <= 0) {
    // Error while reading, or EOF.
    OnUrlRequestCompleted(num_bytes);
    return false;
  }

  // Enforce maximum size bound.
  if (num_bytes + response_body_.size() > request_params_->max_response_bytes) {
    FailRequest(ERR_FILE_TOO_BIG);
    return false;
  }

  // Append the data to |response_body_|.
  response_body_.reserve(num_bytes);
  response_body_.insert(response_body_.end(), read_buffer_->data(),
                        read_buffer_->data() + num_bytes);
  return true;
}

void Job::OnUrlRequestCompleted(int net_error) {
  DCHECK_NE(ERR_IO_PENDING, net_error);
  Error result = static_cast<Error>(net_error);
  OnJobCompleted(result);
}

void Job::OnJobCompleted(Error error) {
  DCHECK_NE(ERR_IO_PENDING, error);
  // Stop the timer and clear the URLRequest.
  Stop();

  std::unique_ptr<Job> delete_this = parent_->RemoveJob(this);

  for (auto* request : requests_) {
    request->OnJobCompleted(this, error, response_body_);
  }

  requests_.clear();
}

void Job::FailRequest(Error error) {
  DCHECK_NE(ERR_IO_PENDING, error);
  int result = url_request_->CancelWithError(error);
  OnUrlRequestCompleted(result);
}

AsyncCertNetFetcherImpl::AsyncCertNetFetcherImpl(URLRequestContext* context)
    : context_(context) {
  // Allow creation to happen from another thread.
  thread_checker_.DetachFromThread();
}

AsyncCertNetFetcherImpl::~AsyncCertNetFetcherImpl() {
  DCHECK(thread_checker_.CalledOnValidThread());
  jobs_.clear();
}

bool JobComparator::operator()(const Job* job1, const Job* job2) const {
  return job1->request_params() < job2->request_params();
}

void AsyncCertNetFetcherImpl::Fetch(
    std::unique_ptr<RequestParams> request_params,
    RequestCore* request) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // If there is an in-progress job that matches the request parameters use it.
  // Otherwise start a new job.
  Job* job = FindJob(*request_params);

  if (!job) {
    job = new Job(std::move(request_params), this);
    jobs_[job] = base::WrapUnique(job);
    job->StartURLRequest(context_);
  }

  return job->AttachRequest(request);
}

struct JobToRequestParamsComparator {
  bool operator()(const JobSet::value_type& job,
                  const RequestParams& value) const {
    return job.first->request_params() < value;
  }
};

Job* AsyncCertNetFetcherImpl::FindJob(const RequestParams& params) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // The JobSet is kept in sorted order so items can be found using binary
  // search.
  JobSet::iterator it = std::lower_bound(jobs_.begin(), jobs_.end(), params,
                                         JobToRequestParamsComparator());
  if (it != jobs_.end() && !(params < (*it).first->request_params()))
    return (*it).first;
  return nullptr;
}

std::unique_ptr<Job> AsyncCertNetFetcherImpl::RemoveJob(Job* job) {
  DCHECK(thread_checker_.CalledOnValidThread());
  auto it = jobs_.find(job);
  CHECK(it != jobs_.end());
  std::unique_ptr<Job> owned_job = std::move(it->second);
  jobs_.erase(it);
  return owned_job;
}

class CertNetFetcherRequestImpl : public CertNetFetcher::Request {
 public:
  explicit CertNetFetcherRequestImpl(scoped_refptr<RequestCore> core)
      : core_(std::move(core)) {
    DCHECK(core_);
  }

  void WaitForResult(Error* error, std::vector<uint8_t>* bytes) override {
    // Should only be called a single time.
    DCHECK(core_);
    core_->WaitForResult(error, bytes);
    core_ = nullptr;
  }

  ~CertNetFetcherRequestImpl() override {
    if (core_)
      core_->Cancel();
  }

 private:
  scoped_refptr<RequestCore> core_;
};

class CertNetFetcherCore
    : public base::RefCountedThreadSafe<CertNetFetcherCore> {
 public:
  explicit CertNetFetcherCore(URLRequestContextGetter* context_getter)
      : context_getter_(context_getter) {}

  void Abandon() {
    GetNetworkTaskRunner()->PostTask(
        FROM_HERE,
        base::Bind(&CertNetFetcherCore::DoAbandonOnNetworkThread, this));
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetNetworkTaskRunner() {
    return context_getter_->GetNetworkTaskRunner();
  }

  void DoFetchOnNetworkThread(std::unique_ptr<RequestParams> request_params,
                              scoped_refptr<RequestCore> request) {
    DCHECK(GetNetworkTaskRunner()->RunsTasksOnCurrentThread());

    if (!impl_) {
      impl_.reset(
          new AsyncCertNetFetcherImpl(context_getter_->GetURLRequestContext()));
    }

    // Don't need to retain a reference to |request| because consume is
    // expected to keep it alive.
    impl_->Fetch(std::move(request_params), request.get());
  }

 private:
  friend class base::RefCountedThreadSafe<CertNetFetcherCore>;

  void DoAbandonOnNetworkThread() {
    DCHECK(GetNetworkTaskRunner()->RunsTasksOnCurrentThread());
    impl_.reset();
  }

  ~CertNetFetcherCore() { DCHECK(!impl_); }

  scoped_refptr<URLRequestContextGetter> context_getter_;

  std::unique_ptr<AsyncCertNetFetcherImpl> impl_;

  DISALLOW_COPY_AND_ASSIGN(CertNetFetcherCore);
};

class CertNetFetcherImpl : public CertNetFetcher {
 public:
  explicit CertNetFetcherImpl(URLRequestContextGetter* context_getter)
      : core_(new CertNetFetcherCore(context_getter)) {}

  ~CertNetFetcherImpl() override { core_->Abandon(); }

  std::unique_ptr<Request> FetchCaIssuers(const GURL& url,
                                          int timeout_milliseconds,
                                          int max_response_bytes) override {
    std::unique_ptr<RequestParams> request_params(new RequestParams);

    request_params->url = url;
    request_params->http_method = HTTP_METHOD_GET;
    request_params->timeout = GetTimeout(timeout_milliseconds);
    request_params->max_response_bytes =
        GetMaxResponseBytes(max_response_bytes, kMaxResponseSizeInBytesForAia);

    return DoFetch(std::move(request_params));
  }

  std::unique_ptr<Request> FetchCrl(const GURL& url,
                                    int timeout_milliseconds,
                                    int max_response_bytes) override {
    std::unique_ptr<RequestParams> request_params(new RequestParams);

    request_params->url = url;
    request_params->http_method = HTTP_METHOD_GET;
    request_params->timeout = GetTimeout(timeout_milliseconds);
    request_params->max_response_bytes =
        GetMaxResponseBytes(max_response_bytes, kMaxResponseSizeInBytesForCrl);

    return DoFetch(std::move(request_params));
  }

  WARN_UNUSED_RESULT std::unique_ptr<Request> FetchOcsp(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes) override {
    std::unique_ptr<RequestParams> request_params(new RequestParams);

    request_params->url = url;
    request_params->http_method = HTTP_METHOD_GET;
    request_params->timeout = GetTimeout(timeout_milliseconds);
    request_params->max_response_bytes =
        GetMaxResponseBytes(max_response_bytes, kMaxResponseSizeInBytesForAia);

    return DoFetch(std::move(request_params));
  }

 private:
  std::unique_ptr<Request> DoFetch(
      std::unique_ptr<RequestParams> request_params) {
    auto task_runner = core_->GetNetworkTaskRunner();
    scoped_refptr<RequestCore> request_core = new RequestCore(task_runner);

    task_runner->PostTask(
        FROM_HERE,
        base::Bind(&CertNetFetcherCore::DoFetchOnNetworkThread, core_,
                   base::Passed(&request_params), request_core));

    return base::MakeUnique<CertNetFetcherRequestImpl>(std::move(request_core));
  }

 private:
  scoped_refptr<CertNetFetcherCore> core_;
};

}  // namespace

std::unique_ptr<CertNetFetcher> CreateCertNetFetcher(
    URLRequestContextGetter* context_getter) {
  return base::MakeUnique<CertNetFetcherImpl>(context_getter);
}

}  // namespace net
