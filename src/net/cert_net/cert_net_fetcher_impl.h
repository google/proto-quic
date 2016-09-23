// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_NET_CERT_NET_FETCHER_H_
#define NET_CERT_NET_CERT_NET_FETCHER_H_

#include <memory>
#include <set>

#include "base/callback.h"
#include "base/macros.h"
#include "base/threading/thread_checker.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"
#include "net/cert/cert_net_fetcher.h"

namespace net {

class URLRequestContext;

// CertNetFetcherImpl is an implementation of CertNetFetcher that uses the
// network stack.
//
// For more details refer to the documentation for the interface.
class NET_EXPORT CertNetFetcherImpl : public CertNetFetcher {
 public:
  // Initializes CertNetFetcherImpl using the specified URLRequestContext for
  // issuing requests. |context| must remain valid for the entire lifetime of
  // the CertNetFetcherImpl.
  explicit CertNetFetcherImpl(URLRequestContext* context);

  // Deletion implicitly cancels any outstanding requests.
  ~CertNetFetcherImpl() override;

  WARN_UNUSED_RESULT std::unique_ptr<Request> FetchCaIssuers(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes,
      const FetchCallback& callback) override;

  WARN_UNUSED_RESULT std::unique_ptr<Request> FetchCrl(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes,
      const FetchCallback& callback) override;

  WARN_UNUSED_RESULT std::unique_ptr<Request> FetchOcsp(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes,
      const FetchCallback& callback) override;

 private:
  class RequestImpl;
  class Job;
  struct JobToRequestParamsComparator;
  struct RequestParams;

  struct JobComparator {
    bool operator()(const Job* job1, const Job* job2) const;
  };

  // Owns the jobs.
  using JobSet = std::set<Job*, JobComparator>;

  // Starts an asynchronous request to fetch the given URL. On completion
  // |callback| will be invoked.
  //
  // Completion of the request will never occur synchronously. In other words it
  // is guaranteed that |callback| will only be invoked once the Fetch*() method
  // has returned.
  WARN_UNUSED_RESULT std::unique_ptr<Request> Fetch(
      std::unique_ptr<RequestParams> request_params,
      const FetchCallback& callback);

  // Finds a job with a matching RequestPararms or returns nullptr if there was
  // no match.
  Job* FindJob(const RequestParams& params);

  // Removes |job| from the in progress jobs and transfers ownership to the
  // caller.
  std::unique_ptr<Job> RemoveJob(Job* job);

  // Indicates which Job is currently executing inside of OnJobCompleted().
  void SetCurrentlyCompletingJob(Job* job);
  void ClearCurrentlyCompletingJob(Job* job);
  bool IsCurrentlyCompletingJob(Job* job);

  // The in-progress jobs. This set does not contain the job which is actively
  // invoking callbacks (OnJobCompleted). Instead that is tracked by
  // |currently_completing_job_|.
  JobSet jobs_;

  // The Job that is currently executing OnJobCompleted(). There can be at most
  // one such job. This pointer is not owned.
  Job* currently_completing_job_;

  // Not owned. CertNetFetcherImpl must outlive the URLRequestContext.
  URLRequestContext* context_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(CertNetFetcherImpl);
};

}  // namespace net

#endif  // NET_CERT_NET_CERT_NET_FETCHER_H_
