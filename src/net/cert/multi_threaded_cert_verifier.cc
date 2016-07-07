// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/multi_threaded_cert_verifier.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/containers/linked_list.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/histogram_macros.h"
#include "base/profiler/scoped_tracker.h"
#include "base/sha1.h"
#include "base/stl_util.h"
#include "base/threading/worker_pool.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "net/base/hash_value.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/log/net_log.h"

#if defined(USE_NSS_CERTS)
#include <private/pprthred.h>  // PR_DetachThread
#endif

namespace net {

////////////////////////////////////////////////////////////////////////////
//
// MultiThreadedCertVerifier is a thread-unsafe object which lives, dies, and is
// operated on a single thread, henceforth referred to as the "origin" thread.
//
// When an incoming Verify() request is received, MultiThreadedCertVerifier
// checks if there is an outstanding "job" (CertVerifierJob) in progress that
// can service the request. If there is, the request is attached to that job.
// Otherwise a new job is started.
//
// A job (CertVerifierJob) is a way to de-duplicate requests that are
// fundamentally doing the same verification. CertVerifierJob is similarly
// thread-unsafe and lives on the origin thread.
//
// To do the actual work, CertVerifierJob posts a task to WorkerPool
// (PostTaskAndReply), and on completion notifies all requests attached to it.
//
// Cancellation:
//
// There are two ways for a request to be cancelled.
//
// (1) When the caller explicitly frees the Request.
//
//     If the request was in-flight (attached to a job), then it is detached.
//     Note that no effort is made to reap jobs which have no attached requests.
//     (Because the worker task isn't cancelable).
//
// (2) When the MultiThreadedCertVerifier is deleted.
//
//     This automatically cancels all outstanding requests. This is accomplished
//     by deleting each of the jobs owned by the MultiThreadedCertVerifier,
//     whose destructor in turn marks each attached request as canceled.
//
// TODO(eroman): If the MultiThreadedCertVerifier is deleted from within a
// callback, the remaining requests in the completing job will NOT be cancelled.

namespace {

std::unique_ptr<base::Value> CertVerifyResultCallback(
    const CertVerifyResult& verify_result,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> results(new base::DictionaryValue());
  results->SetBoolean("has_md5", verify_result.has_md5);
  results->SetBoolean("has_md2", verify_result.has_md2);
  results->SetBoolean("has_md4", verify_result.has_md4);
  results->SetBoolean("is_issued_by_known_root",
                      verify_result.is_issued_by_known_root);
  results->SetBoolean("is_issued_by_additional_trust_anchor",
                      verify_result.is_issued_by_additional_trust_anchor);
  results->SetBoolean("common_name_fallback_used",
                      verify_result.common_name_fallback_used);
  results->SetInteger("cert_status", verify_result.cert_status);
  results->Set("verified_cert",
               NetLogX509CertificateCallback(verify_result.verified_cert.get(),
                                             capture_mode));

  std::unique_ptr<base::ListValue> hashes(new base::ListValue());
  for (std::vector<HashValue>::const_iterator it =
           verify_result.public_key_hashes.begin();
       it != verify_result.public_key_hashes.end();
       ++it) {
    hashes->AppendString(it->ToString());
  }
  results->Set("public_key_hashes", std::move(hashes));

  return std::move(results);
}

// Helper structure used to keep |verify_result| alive for the lifetime of
// the verification on the worker thread, and to communicate it back to the
// calling thread.
struct ResultHelper {
  int error;
  CertVerifyResult result;
};

}  // namespace

// Represents the output and result callback of a request. The
// CertVerifierRequest is owned by the caller that initiated the call to
// CertVerifier::Verify().
class CertVerifierRequest : public base::LinkNode<CertVerifierRequest>,
                            public CertVerifier::Request {
 public:
  CertVerifierRequest(CertVerifierJob* job,
                      const CompletionCallback& callback,
                      CertVerifyResult* verify_result,
                      const BoundNetLog& net_log)
      : job_(job),
        callback_(callback),
        verify_result_(verify_result),
        net_log_(net_log) {
    net_log_.BeginEvent(NetLog::TYPE_CERT_VERIFIER_REQUEST);
  }

  // Cancels the request.
  ~CertVerifierRequest() override {
    if (job_) {
      // Cancel the outstanding request.
      net_log_.AddEvent(NetLog::TYPE_CANCELLED);
      net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_REQUEST);

      // Remove the request from the Job. No attempt is made to cancel the job
      // even though it may no longer have any requests attached to it. Because
      // it is running on a worker thread aborting it isn't feasible.
      RemoveFromList();
    }
  }

  // Copies the contents of |verify_result| to the caller's
  // CertVerifyResult and calls the callback.
  void Post(const ResultHelper& verify_result) {
    DCHECK(job_);
    job_ = nullptr;

    net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_REQUEST);
    *verify_result_ = verify_result.result;

    base::ResetAndReturn(&callback_).Run(verify_result.error);
  }

  void OnJobCancelled() {
    job_ = nullptr;
    callback_.Reset();
  }

  const BoundNetLog& net_log() const { return net_log_; }

 private:
  CertVerifierJob* job_;  // Not owned.
  CompletionCallback callback_;
  CertVerifyResult* verify_result_;
  const BoundNetLog net_log_;
};

// DoVerifyOnWorkerThread runs the verification synchronously on a worker
// thread. The output parameters (error and result) must remain alive.
void DoVerifyOnWorkerThread(const scoped_refptr<CertVerifyProc>& verify_proc,
                            const scoped_refptr<X509Certificate>& cert,
                            const std::string& hostname,
                            const std::string& ocsp_response,
                            int flags,
                            const scoped_refptr<CRLSet>& crl_set,
                            const CertificateList& additional_trust_anchors,
                            int* error,
                            CertVerifyResult* result) {
  TRACE_EVENT0("net", "DoVerifyOnWorkerThread");
  *error = verify_proc->Verify(cert.get(), hostname, ocsp_response, flags,
                               crl_set.get(), additional_trust_anchors, result);

#if defined(USE_NSS_CERTS)
  // Detach the thread from NSPR.
  // Calling NSS functions attaches the thread to NSPR, which stores
  // the NSPR thread ID in thread-specific data.
  // The threads in our thread pool terminate after we have called
  // PR_Cleanup.  Unless we detach them from NSPR, net_unittests gets
  // segfaults on shutdown when the threads' thread-specific data
  // destructors run.
  PR_DetachThread();
#endif
}

// CertVerifierJob lives only on the verifier's origin message loop.
class CertVerifierJob {
 public:
  CertVerifierJob(const CertVerifier::RequestParams& key,
                  NetLog* net_log,
                  MultiThreadedCertVerifier* cert_verifier)
      : key_(key),
        start_time_(base::TimeTicks::Now()),
        net_log_(BoundNetLog::Make(net_log, NetLog::SOURCE_CERT_VERIFIER_JOB)),
        cert_verifier_(cert_verifier),
        is_first_job_(false),
        weak_ptr_factory_(this) {
    net_log_.BeginEvent(NetLog::TYPE_CERT_VERIFIER_JOB,
                        base::Bind(&NetLogX509CertificateCallback,
                                   base::Unretained(key.certificate().get())));
  }

  // Indicates whether this was the first job started by the CertVerifier. This
  // is only used for logging certain UMA stats.
  void set_is_first_job(bool is_first_job) { is_first_job_ = is_first_job; }

  const CertVerifier::RequestParams& key() const { return key_; }

  // Posts a task to the worker pool to do the verification. Once the
  // verification has completed on the worker thread, it will call
  // OnJobCompleted() on the origin thread.
  bool Start(const scoped_refptr<CertVerifyProc>& verify_proc,
             const scoped_refptr<CRLSet>& crl_set) {
    // Owned by the bound reply callback.
    std::unique_ptr<ResultHelper> owned_result(new ResultHelper());

    // Parameter evaluation order is undefined in C++. Ensure the pointer value
    // is gotten before calling base::Passed().
    auto* result = owned_result.get();

    return base::WorkerPool::PostTaskAndReply(
        FROM_HERE,
        base::Bind(&DoVerifyOnWorkerThread, verify_proc, key_.certificate(),
                   key_.hostname(), key_.ocsp_response(), key_.flags(), crl_set,
                   key_.additional_trust_anchors(), &result->error,
                   &result->result),
        base::Bind(&CertVerifierJob::OnJobCompleted,
                   weak_ptr_factory_.GetWeakPtr(), base::Passed(&owned_result)),
        true /* task is slow */);
  }

  ~CertVerifierJob() {
    // If the job is in progress, cancel it.
    if (cert_verifier_) {
      cert_verifier_ = nullptr;

      net_log_.AddEvent(NetLog::TYPE_CANCELLED);
      net_log_.EndEvent(NetLog::TYPE_CERT_VERIFIER_JOB);

      // Notify each request of the cancellation.
      for (base::LinkNode<CertVerifierRequest>* it = requests_.head();
           it != requests_.end(); it = it->next()) {
        it->value()->OnJobCancelled();
      }
    }
  }

  // Creates and attaches a request to the Job.
  std::unique_ptr<CertVerifierRequest> CreateRequest(
      const CompletionCallback& callback,
      CertVerifyResult* verify_result,
      const BoundNetLog& net_log) {
    std::unique_ptr<CertVerifierRequest> request(
        new CertVerifierRequest(this, callback, verify_result, net_log));

    request->net_log().AddEvent(
        NetLog::TYPE_CERT_VERIFIER_REQUEST_BOUND_TO_JOB,
        net_log_.source().ToEventParametersCallback());

    requests_.Append(request.get());
    return request;
  }

 private:
  using RequestList = base::LinkedList<CertVerifierRequest>;

  // Called on completion of the Job to log UMA metrics and NetLog events.
  void LogMetrics(const ResultHelper& verify_result) {
    net_log_.EndEvent(
        NetLog::TYPE_CERT_VERIFIER_JOB,
        base::Bind(&CertVerifyResultCallback, verify_result.result));
    base::TimeDelta latency = base::TimeTicks::Now() - start_time_;
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.CertVerifier_Job_Latency",
                               latency,
                               base::TimeDelta::FromMilliseconds(1),
                               base::TimeDelta::FromMinutes(10),
                               100);
    if (is_first_job_) {
      UMA_HISTOGRAM_CUSTOM_TIMES("Net.CertVerifier_First_Job_Latency",
                                 latency,
                                 base::TimeDelta::FromMilliseconds(1),
                                 base::TimeDelta::FromMinutes(10),
                                 100);
    }
  }

  void OnJobCompleted(std::unique_ptr<ResultHelper> verify_result) {
    TRACE_EVENT0("net", "CertVerifierJob::OnJobCompleted");
    std::unique_ptr<CertVerifierJob> keep_alive =
        cert_verifier_->RemoveJob(this);

    LogMetrics(*verify_result);
    cert_verifier_ = nullptr;

    // TODO(eroman): If the cert_verifier_ is deleted from within one of the
    // callbacks, any remaining requests for that job should be cancelled. Right
    // now they will be called.
    while (!requests_.empty()) {
      base::LinkNode<CertVerifierRequest>* request = requests_.head();
      request->RemoveFromList();
      request->value()->Post(*verify_result);
    }
  }

  const CertVerifier::RequestParams key_;
  // The tick count of when the job started. This is used to measure how long
  // the job actually took to complete.
  const base::TimeTicks start_time_;

  RequestList requests_;  // Non-owned.

  const BoundNetLog net_log_;
  MultiThreadedCertVerifier* cert_verifier_;  // Non-owned.

  bool is_first_job_;
  base::WeakPtrFactory<CertVerifierJob> weak_ptr_factory_;
};

MultiThreadedCertVerifier::MultiThreadedCertVerifier(
    CertVerifyProc* verify_proc)
    : requests_(0), inflight_joins_(0), verify_proc_(verify_proc) {}

MultiThreadedCertVerifier::~MultiThreadedCertVerifier() {
  STLDeleteElements(&inflight_);
}

int MultiThreadedCertVerifier::Verify(const RequestParams& params,
                                      CRLSet* crl_set,
                                      CertVerifyResult* verify_result,
                                      const CompletionCallback& callback,
                                      std::unique_ptr<Request>* out_req,
                                      const BoundNetLog& net_log) {
  out_req->reset();

  DCHECK(CalledOnValidThread());

  if (callback.is_null() || !verify_result || params.hostname().empty())
    return ERR_INVALID_ARGUMENT;

  requests_++;

  // See if an identical request is currently in flight.
  CertVerifierJob* job = FindJob(params);
  if (job) {
    // An identical request is in flight already. We'll just attach our
    // callback.
    inflight_joins_++;
  } else {
    // Need to make a new job.
    std::unique_ptr<CertVerifierJob> new_job(
        new CertVerifierJob(params, net_log.net_log(), this));

    if (!new_job->Start(verify_proc_, crl_set)) {
      // TODO(wtc): log to the NetLog.
      LOG(ERROR) << "CertVerifierJob couldn't be started.";
      return ERR_INSUFFICIENT_RESOURCES;  // Just a guess.
    }

    job = new_job.release();
    inflight_.insert(job);

    if (requests_ == 1)
      job->set_is_first_job(true);
  }

  std::unique_ptr<CertVerifierRequest> request =
      job->CreateRequest(callback, verify_result, net_log);
  *out_req = std::move(request);
  return ERR_IO_PENDING;
}

bool MultiThreadedCertVerifier::SupportsOCSPStapling() {
  return verify_proc_->SupportsOCSPStapling();
}

bool MultiThreadedCertVerifier::JobComparator::operator()(
    const CertVerifierJob* job1,
    const CertVerifierJob* job2) const {
  return job1->key() < job2->key();
}

std::unique_ptr<CertVerifierJob> MultiThreadedCertVerifier::RemoveJob(
    CertVerifierJob* job) {
  DCHECK(CalledOnValidThread());
  bool erased_job = inflight_.erase(job) == 1;
  DCHECK(erased_job);
  return base::WrapUnique(job);
}

struct MultiThreadedCertVerifier::JobToRequestParamsComparator {
  bool operator()(const CertVerifierJob* job,
                  const CertVerifier::RequestParams& value) const {
    return job->key() < value;
  }
};

CertVerifierJob* MultiThreadedCertVerifier::FindJob(const RequestParams& key) {
  DCHECK(CalledOnValidThread());

  // The JobSet is kept in sorted order so items can be found using binary
  // search.
  auto it = std::lower_bound(inflight_.begin(), inflight_.end(), key,
                             JobToRequestParamsComparator());
  if (it != inflight_.end() && !(key < (*it)->key()))
    return *it;
  return nullptr;
}

}  // namespace net
