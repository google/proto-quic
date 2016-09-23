// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_resolver_v8_tracing.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/cancellation_flag.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "net/base/address_list.h"
#include "net/base/net_errors.h"
#include "net/base/network_interfaces.h"
#include "net/dns/host_resolver.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver_error_observer.h"
#include "net/proxy/proxy_resolver_v8.h"

// The intent of this class is explained in the design document:
// https://docs.google.com/a/chromium.org/document/d/16Ij5OcVnR3s0MH4Z5XkhI9VTPoMJdaBn9rKreAmGOdE/edit
//
// In a nutshell, PAC scripts are Javascript programs and may depend on
// network I/O, by calling functions like dnsResolve().
//
// This is problematic since functions such as dnsResolve() will block the
// Javascript execution until the DNS result is availble, thereby stalling the
// PAC thread, which hurts the ability to process parallel proxy resolves.
// An obvious solution is to simply start more PAC threads, however this scales
// poorly, which hurts the ability to process parallel proxy resolves.
//
// The solution in ProxyResolverV8Tracing is to model PAC scripts as being
// deterministic, and depending only on the inputted URL. When the script
// issues a dnsResolve() for a yet unresolved hostname, the Javascript
// execution is "aborted", and then re-started once the DNS result is
// known.
namespace net {

namespace {

// Upper bound on how many *unique* DNS resolves a PAC script is allowed
// to make. This is a failsafe both for scripts that do a ridiculous
// number of DNS resolves, as well as scripts which are misbehaving
// under the tracing optimization. It is not expected to hit this normally.
const size_t kMaxUniqueResolveDnsPerExec = 20;

// Approximate number of bytes to use for buffering alerts() and errors.
// This is a failsafe in case repeated executions of the script causes
// too much memory bloat. It is not expected for well behaved scripts to
// hit this. (In fact normal scripts should not even have alerts() or errors).
const size_t kMaxAlertsAndErrorsBytes = 2048;

// The Job class is responsible for executing GetProxyForURL() and
// creating ProxyResolverV8 instances, since both of these operations share
// similar code.
//
// The DNS for these operations can operate in either blocking or
// non-blocking mode. Blocking mode is used as a fallback when the PAC script
// seems to be misbehaving under the tracing optimization.
//
// Note that this class runs on both the origin thread and a worker
// thread. Most methods are expected to be used exclusively on one thread
// or the other.
//
// The lifetime of Jobs does not exceed that of the ProxyResolverV8TracingImpl
// that spawned it. Destruction might happen on either the origin thread or the
// worker thread.
class Job : public base::RefCountedThreadSafe<Job>,
            public ProxyResolverV8::JSBindings {
 public:
  struct Params {
    Params(
        const scoped_refptr<base::SingleThreadTaskRunner>& worker_task_runner,
        int* num_outstanding_callbacks)
        : v8_resolver(nullptr),
          worker_task_runner(worker_task_runner),
          num_outstanding_callbacks(num_outstanding_callbacks) {}

    ProxyResolverV8* v8_resolver;
    scoped_refptr<base::SingleThreadTaskRunner> worker_task_runner;
    int* num_outstanding_callbacks;
  };
  // |params| is non-owned. It contains the parameters for this Job, and must
  // outlive it.
  Job(const Params* params,
      std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings);

  // Called from origin thread.
  void StartCreateV8Resolver(
      const scoped_refptr<ProxyResolverScriptData>& script_data,
      std::unique_ptr<ProxyResolverV8>* resolver,
      const CompletionCallback& callback);

  // Called from origin thread.
  void StartGetProxyForURL(const GURL& url,
                           ProxyInfo* results,
                           const CompletionCallback& callback);

  // Called from origin thread.
  void Cancel();

  // Called from origin thread.
  LoadState GetLoadState() const;

 private:
  typedef std::map<std::string, std::string> DnsCache;
  friend class base::RefCountedThreadSafe<Job>;

  enum Operation {
    CREATE_V8_RESOLVER,
    GET_PROXY_FOR_URL,
  };

  struct AlertOrError {
    bool is_alert;
    int line_number;
    base::string16 message;
  };

  ~Job() override;

  void CheckIsOnWorkerThread() const;
  void CheckIsOnOriginThread() const;

  void SetCallback(const CompletionCallback& callback);
  void ReleaseCallback();

  ProxyResolverV8* v8_resolver();
  const scoped_refptr<base::SingleThreadTaskRunner>& worker_task_runner();
  HostResolver* host_resolver();

  // Invokes the user's callback.
  void NotifyCaller(int result);
  void NotifyCallerOnOriginLoop(int result);

  void Start(Operation op, bool blocking_dns,
             const CompletionCallback& callback);

  void ExecuteBlocking();
  void ExecuteNonBlocking();
  int ExecuteProxyResolver();

  // Implementation of ProxyResolverv8::JSBindings
  bool ResolveDns(const std::string& host,
                  ResolveDnsOperation op,
                  std::string* output,
                  bool* terminate) override;
  void Alert(const base::string16& message) override;
  void OnError(int line_number, const base::string16& error) override;

  bool ResolveDnsBlocking(const std::string& host,
                          ResolveDnsOperation op,
                          std::string* output);

  bool ResolveDnsNonBlocking(const std::string& host,
                             ResolveDnsOperation op,
                             std::string* output,
                             bool* terminate);

  bool PostDnsOperationAndWait(const std::string& host,
                               ResolveDnsOperation op,
                               bool* completed_synchronously)
                               WARN_UNUSED_RESULT;

  void DoDnsOperation();
  void OnDnsOperationComplete(int result);

  void ScheduleRestartWithBlockingDns();

  bool GetDnsFromLocalCache(const std::string& host, ResolveDnsOperation op,
                            std::string* output, bool* return_value);

  void SaveDnsToLocalCache(const std::string& host,
                           ResolveDnsOperation op,
                           int net_error,
                           const AddressList& addresses);

  // Builds a RequestInfo to service the specified PAC DNS operation.
  static HostResolver::RequestInfo MakeDnsRequestInfo(const std::string& host,
                                                      ResolveDnsOperation op);

  // Makes a key for looking up |host, op| in |dns_cache_|. Strings are used for
  // convenience, to avoid defining custom comparators.
  static std::string MakeDnsCacheKey(const std::string& host,
                                     ResolveDnsOperation op);

  void HandleAlertOrError(bool is_alert, int line_number,
                          const base::string16& message);
  void DispatchBufferedAlertsAndErrors();
  void DispatchAlertOrErrorOnOriginThread(bool is_alert,
                                          int line_number,
                                          const base::string16& message);

  // The thread which called into ProxyResolverV8TracingImpl, and on which the
  // completion callback is expected to run.
  scoped_refptr<base::SingleThreadTaskRunner> origin_runner_;

  // The Parameters for this Job.
  // Initialized on origin thread and then accessed from both threads.
  const Params* const params_;

  std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings_;

  // The callback to run (on the origin thread) when the Job finishes.
  // Should only be accessed from origin thread.
  CompletionCallback callback_;

  // Flag to indicate whether the request has been cancelled.
  base::CancellationFlag cancelled_;

  // The operation that this Job is running.
  // Initialized on origin thread and then accessed from both threads.
  Operation operation_;

  // The DNS mode for this Job.
  // Initialized on origin thread, mutated on worker thread, and accessed
  // by both the origin thread and worker thread.
  bool blocking_dns_;

  // Used to block the worker thread on a DNS operation taking place on the
  // origin thread.
  base::WaitableEvent event_;

  // Map of DNS operations completed so far. Written into on the origin thread
  // and read on the worker thread.
  DnsCache dns_cache_;

  // The job holds a reference to itself to ensure that it remains alive until
  // either completion or cancellation.
  scoped_refptr<Job> owned_self_reference_;

  // -------------------------------------------------------
  // State specific to CREATE_V8_RESOLVER.
  // -------------------------------------------------------

  scoped_refptr<ProxyResolverScriptData> script_data_;
  std::unique_ptr<ProxyResolverV8>* resolver_out_;

  // -------------------------------------------------------
  // State specific to GET_PROXY_FOR_URL.
  // -------------------------------------------------------

  ProxyInfo* user_results_;  // Owned by caller, lives on origin thread.
  GURL url_;
  ProxyInfo results_;

  // ---------------------------------------------------------------------------
  // State for ExecuteNonBlocking()
  // ---------------------------------------------------------------------------
  // These variables are used exclusively on the worker thread and are only
  // meaningful when executing inside of ExecuteNonBlocking().

  // Whether this execution was abandoned due to a missing DNS dependency.
  bool abandoned_;

  // Number of calls made to ResolveDns() by this execution.
  int num_dns_;

  // Sequence of calls made to Alert() or OnError() by this execution.
  std::vector<AlertOrError> alerts_and_errors_;
  size_t alerts_and_errors_byte_cost_;  // Approximate byte cost of the above.

  // Number of calls made to ResolveDns() by the PREVIOUS execution.
  int last_num_dns_;

  // Whether the current execution needs to be restarted in blocking mode.
  bool should_restart_with_blocking_dns_;

  // ---------------------------------------------------------------------------
  // State for pending DNS request.
  // ---------------------------------------------------------------------------

  // Handle to the outstanding request in the HostResolver, or NULL.
  // This is mutated and used on the origin thread, however it may be read by
  // the worker thread for some DCHECKS().
  std::unique_ptr<HostResolver::Request> pending_dns_;

  // Indicates if the outstanding DNS request completed synchronously. Written
  // on the origin thread, and read by the worker thread.
  bool pending_dns_completed_synchronously_;

  // These are the inputs to DoDnsOperation(). Written on the worker thread,
  // read by the origin thread.
  std::string pending_dns_host_;
  ResolveDnsOperation pending_dns_op_;

  // This contains the resolved address list that DoDnsOperation() fills in.
  // Used exclusively on the origin thread.
  AddressList pending_dns_addresses_;
};

class ProxyResolverV8TracingImpl : public ProxyResolverV8Tracing,
                                   public base::NonThreadSafe {
 public:
  ProxyResolverV8TracingImpl(std::unique_ptr<base::Thread> thread,
                             std::unique_ptr<ProxyResolverV8> resolver,
                             std::unique_ptr<Job::Params> job_params);

  ~ProxyResolverV8TracingImpl() override;

  // ProxyResolverV8Tracing overrides.
  void GetProxyForURL(const GURL& url,
                      ProxyInfo* results,
                      const CompletionCallback& callback,
                      ProxyResolver::RequestHandle* request,
                      std::unique_ptr<Bindings> bindings) override;
  void CancelRequest(ProxyResolver::RequestHandle request) override;
  LoadState GetLoadState(ProxyResolver::RequestHandle request) const override;

 private:
  // The worker thread on which the ProxyResolverV8 will be run.
  std::unique_ptr<base::Thread> thread_;
  std::unique_ptr<ProxyResolverV8> v8_resolver_;

  std::unique_ptr<Job::Params> job_params_;

  // The number of outstanding (non-cancelled) jobs.
  int num_outstanding_callbacks_;

  DISALLOW_COPY_AND_ASSIGN(ProxyResolverV8TracingImpl);
};

Job::Job(const Job::Params* params,
         std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings)
    : origin_runner_(base::ThreadTaskRunnerHandle::Get()),
      params_(params),
      bindings_(std::move(bindings)),
      event_(base::WaitableEvent::ResetPolicy::MANUAL,
             base::WaitableEvent::InitialState::NOT_SIGNALED),
      last_num_dns_(0) {
  CheckIsOnOriginThread();
}

void Job::StartCreateV8Resolver(
    const scoped_refptr<ProxyResolverScriptData>& script_data,
    std::unique_ptr<ProxyResolverV8>* resolver,
    const CompletionCallback& callback) {
  CheckIsOnOriginThread();

  resolver_out_ = resolver;
  script_data_ = script_data;

  // Script initialization uses blocking DNS since there isn't any
  // advantage to using non-blocking mode here. That is because the
  // parent ProxyService can't submit any ProxyResolve requests until
  // initialization has completed successfully!
  Start(CREATE_V8_RESOLVER, true /*blocking*/, callback);
}

void Job::StartGetProxyForURL(const GURL& url,
                              ProxyInfo* results,
                              const CompletionCallback& callback) {
  CheckIsOnOriginThread();

  url_ = url;
  user_results_ = results;

  Start(GET_PROXY_FOR_URL, false /*non-blocking*/, callback);
}

void Job::Cancel() {
  CheckIsOnOriginThread();

  // There are several possibilities to consider for cancellation:
  // (a) The job has been posted to the worker thread, however script execution
  //     has not yet started.
  // (b) The script is executing on the worker thread.
  // (c) The script is executing on the worker thread, however is blocked inside
  //     of dnsResolve() waiting for a response from the origin thread.
  // (d) Nothing is running on the worker thread, however the host resolver has
  //     a pending DNS request which upon completion will restart the script
  //     execution.
  // (e) The worker thread has a pending task to restart execution, which was
  //     posted after the DNS dependency was resolved and saved to local cache.
  // (f) The script execution completed entirely, and posted a task to the
  //     origin thread to notify the caller.
  //
  // |cancelled_| is read on both the origin thread and worker thread. The
  // code that runs on the worker thread is littered with checks on
  // |cancelled_| to break out early.
  cancelled_.Set();

  ReleaseCallback();

  pending_dns_.reset();

  // The worker thread might be blocked waiting for DNS.
  event_.Signal();

  bindings_.reset();
  owned_self_reference_ = NULL;
}

LoadState Job::GetLoadState() const {
  CheckIsOnOriginThread();

  if (pending_dns_)
    return LOAD_STATE_RESOLVING_HOST_IN_PROXY_SCRIPT;

  return LOAD_STATE_RESOLVING_PROXY_FOR_URL;
}

Job::~Job() {
  DCHECK(!pending_dns_);
  DCHECK(callback_.is_null());
  DCHECK(!bindings_);
}

void Job::CheckIsOnWorkerThread() const {
  DCHECK(params_->worker_task_runner->BelongsToCurrentThread());
}

void Job::CheckIsOnOriginThread() const {
  DCHECK(origin_runner_->BelongsToCurrentThread());
}

void Job::SetCallback(const CompletionCallback& callback) {
  CheckIsOnOriginThread();
  DCHECK(callback_.is_null());
  (*params_->num_outstanding_callbacks)++;
  callback_ = callback;
}

void Job::ReleaseCallback() {
  CheckIsOnOriginThread();
  DCHECK(!callback_.is_null());
  CHECK_GT(*params_->num_outstanding_callbacks, 0);
  (*params_->num_outstanding_callbacks)--;
  callback_.Reset();

  // For good measure, clear this other user-owned pointer.
  user_results_ = NULL;
}

ProxyResolverV8* Job::v8_resolver() {
  return params_->v8_resolver;
}

const scoped_refptr<base::SingleThreadTaskRunner>& Job::worker_task_runner() {
  return params_->worker_task_runner;
}

HostResolver* Job::host_resolver() {
  return bindings_->GetHostResolver();
}

void Job::NotifyCaller(int result) {
  CheckIsOnWorkerThread();

  origin_runner_->PostTask(
      FROM_HERE, base::Bind(&Job::NotifyCallerOnOriginLoop, this, result));
}

void Job::NotifyCallerOnOriginLoop(int result) {
  CheckIsOnOriginThread();

  if (cancelled_.IsSet())
    return;

  DispatchBufferedAlertsAndErrors();

  // This isn't the ordinary execution flow, however it is exercised by
  // unit-tests.
  if (cancelled_.IsSet())
    return;

  DCHECK(!callback_.is_null());
  DCHECK(!pending_dns_);

  if (operation_ == GET_PROXY_FOR_URL) {
    *user_results_ = results_;
  }

  CompletionCallback callback = callback_;
  ReleaseCallback();
  callback.Run(result);

  bindings_.reset();
  owned_self_reference_ = NULL;
}

void Job::Start(Operation op,
                bool blocking_dns,
                const CompletionCallback& callback) {
  CheckIsOnOriginThread();

  operation_ = op;
  blocking_dns_ = blocking_dns;
  SetCallback(callback);

  owned_self_reference_ = this;

  worker_task_runner()->PostTask(
      FROM_HERE, blocking_dns_ ? base::Bind(&Job::ExecuteBlocking, this)
                               : base::Bind(&Job::ExecuteNonBlocking, this));
}

void Job::ExecuteBlocking() {
  CheckIsOnWorkerThread();
  DCHECK(blocking_dns_);

  if (cancelled_.IsSet())
    return;

  NotifyCaller(ExecuteProxyResolver());
}

void Job::ExecuteNonBlocking() {
  CheckIsOnWorkerThread();
  DCHECK(!blocking_dns_);

  if (cancelled_.IsSet())
    return;

  // Reset state for the current execution.
  abandoned_ = false;
  num_dns_ = 0;
  alerts_and_errors_.clear();
  alerts_and_errors_byte_cost_ = 0;
  should_restart_with_blocking_dns_ = false;

  int result = ExecuteProxyResolver();

  if (should_restart_with_blocking_dns_) {
    DCHECK(!blocking_dns_);
    DCHECK(abandoned_);
    blocking_dns_ = true;
    ExecuteBlocking();
    return;
  }

  if (abandoned_)
    return;

  NotifyCaller(result);
}

int Job::ExecuteProxyResolver() {
  TRACE_EVENT0("net", "Job::ExecuteProxyResolver");
  int result = ERR_UNEXPECTED;  // Initialized to silence warnings.

  switch (operation_) {
    case CREATE_V8_RESOLVER: {
      std::unique_ptr<ProxyResolverV8> resolver;
      result = ProxyResolverV8::Create(script_data_, this, &resolver);
      if (result == OK)
        *resolver_out_ = std::move(resolver);
      break;
    }
    case GET_PROXY_FOR_URL: {
      result = v8_resolver()->GetProxyForURL(
          url_,
          // Important: Do not write directly into |user_results_|, since if the
          // request were to be cancelled from the origin thread, must guarantee
          // that |user_results_| is not accessed anymore.
          &results_, this);
      break;
    }
  }

  return result;
}

bool Job::ResolveDns(const std::string& host,
                     ResolveDnsOperation op,
                     std::string* output,
                     bool* terminate) {
  if (cancelled_.IsSet()) {
    *terminate = true;
    return false;
  }

  if ((op == DNS_RESOLVE || op == DNS_RESOLVE_EX) && host.empty()) {
    // a DNS resolve with an empty hostname is considered an error.
    return false;
  }

  return blocking_dns_ ?
      ResolveDnsBlocking(host, op, output) :
      ResolveDnsNonBlocking(host, op, output, terminate);
}

void Job::Alert(const base::string16& message) {
  HandleAlertOrError(true, -1, message);
}

void Job::OnError(int line_number, const base::string16& error) {
  HandleAlertOrError(false, line_number, error);
}

bool Job::ResolveDnsBlocking(const std::string& host,
                             ResolveDnsOperation op,
                             std::string* output) {
  CheckIsOnWorkerThread();

  // Check if the DNS result for this host has already been cached.
  bool rv;
  if (GetDnsFromLocalCache(host, op, output, &rv)) {
    // Yay, cache hit!
    return rv;
  }

  if (dns_cache_.size() >= kMaxUniqueResolveDnsPerExec) {
    // Safety net for scripts with unexpectedly many DNS calls.
    // We will continue running to completion, but will fail every
    // subsequent DNS request.
    return false;
  }

  if (!PostDnsOperationAndWait(host, op, NULL))
    return false;  // Was cancelled.

  CHECK(GetDnsFromLocalCache(host, op, output, &rv));
  return rv;
}

bool Job::ResolveDnsNonBlocking(const std::string& host,
                                ResolveDnsOperation op,
                                std::string* output,
                                bool* terminate) {
  CheckIsOnWorkerThread();

  if (abandoned_) {
    // If this execution was already abandoned can fail right away. Only 1 DNS
    // dependency will be traced at a time (for more predictable outcomes).
    return false;
  }

  num_dns_ += 1;

  // Check if the DNS result for this host has already been cached.
  bool rv;
  if (GetDnsFromLocalCache(host, op, output, &rv)) {
    // Yay, cache hit!
    return rv;
  }

  if (num_dns_ <= last_num_dns_) {
    // The sequence of DNS operations is different from last time!
    ScheduleRestartWithBlockingDns();
    *terminate = true;
    return false;
  }

  if (dns_cache_.size() >= kMaxUniqueResolveDnsPerExec) {
    // Safety net for scripts with unexpectedly many DNS calls.
    return false;
  }

  DCHECK(!should_restart_with_blocking_dns_);

  bool completed_synchronously;
  if (!PostDnsOperationAndWait(host, op, &completed_synchronously))
    return false;  // Was cancelled.

  if (completed_synchronously) {
    CHECK(GetDnsFromLocalCache(host, op, output, &rv));
    return rv;
  }

  // Otherwise if the result was not in the cache, then a DNS request has
  // been started. Abandon this invocation of FindProxyForURL(), it will be
  // restarted once the DNS request completes.
  abandoned_ = true;
  *terminate = true;
  last_num_dns_ = num_dns_;
  return false;
}

bool Job::PostDnsOperationAndWait(const std::string& host,
                                  ResolveDnsOperation op,
                                  bool* completed_synchronously) {
  // Post the DNS request to the origin thread.
  DCHECK(!pending_dns_);
  pending_dns_host_ = host;
  pending_dns_op_ = op;
  origin_runner_->PostTask(FROM_HERE, base::Bind(&Job::DoDnsOperation, this));

  event_.Wait();
  event_.Reset();

  if (cancelled_.IsSet())
    return false;

  if (completed_synchronously)
    *completed_synchronously = pending_dns_completed_synchronously_;

  return true;
}

void Job::DoDnsOperation() {
  CheckIsOnOriginThread();
  DCHECK(!pending_dns_);

  if (cancelled_.IsSet())
    return;

  std::unique_ptr<HostResolver::Request> dns_request;
  int result = host_resolver()->Resolve(
      MakeDnsRequestInfo(pending_dns_host_, pending_dns_op_), DEFAULT_PRIORITY,
      &pending_dns_addresses_, base::Bind(&Job::OnDnsOperationComplete, this),
      &dns_request, bindings_->GetNetLogWithSource());

  pending_dns_completed_synchronously_ = result != ERR_IO_PENDING;

  // Check if the request was cancelled as a side-effect of calling into the
  // HostResolver. This isn't the ordinary execution flow, however it is
  // exercised by unit-tests.
  if (cancelled_.IsSet())
    return;

  if (pending_dns_completed_synchronously_) {
    OnDnsOperationComplete(result);
  } else {
    DCHECK(dns_request);
    pending_dns_ = std::move(dns_request);
    // OnDnsOperationComplete() will be called by host resolver on completion.
  }

  if (!blocking_dns_) {
    // The worker thread always blocks waiting to see if the result can be
    // serviced from cache before restarting.
    event_.Signal();
  }
}

void Job::OnDnsOperationComplete(int result) {
  CheckIsOnOriginThread();

  DCHECK(!cancelled_.IsSet());
  DCHECK(pending_dns_completed_synchronously_ == (pending_dns_ == NULL));

  SaveDnsToLocalCache(pending_dns_host_, pending_dns_op_, result,
                      pending_dns_addresses_);
  pending_dns_.reset();

  if (blocking_dns_) {
    event_.Signal();
    return;
  }

  if (!blocking_dns_ && !pending_dns_completed_synchronously_) {
    // Restart. This time it should make more progress due to having
    // cached items.
    worker_task_runner()->PostTask(FROM_HERE,
                                   base::Bind(&Job::ExecuteNonBlocking, this));
  }
}

void Job::ScheduleRestartWithBlockingDns() {
  CheckIsOnWorkerThread();

  DCHECK(!should_restart_with_blocking_dns_);
  DCHECK(!abandoned_);
  DCHECK(!blocking_dns_);

  abandoned_ = true;

  // The restart will happen after ExecuteNonBlocking() finishes.
  should_restart_with_blocking_dns_ = true;
}

bool Job::GetDnsFromLocalCache(const std::string& host,
                               ResolveDnsOperation op,
                               std::string* output,
                               bool* return_value) {
  CheckIsOnWorkerThread();

  DnsCache::const_iterator it = dns_cache_.find(MakeDnsCacheKey(host, op));
  if (it == dns_cache_.end())
    return false;

  *output = it->second;
  *return_value = !it->second.empty();
  return true;
}

void Job::SaveDnsToLocalCache(const std::string& host,
                              ResolveDnsOperation op,
                              int net_error,
                              const AddressList& addresses) {
  CheckIsOnOriginThread();

  // Serialize the result into a string to save to the cache.
  std::string cache_value;
  if (net_error != OK) {
    cache_value = std::string();
  } else if (op == DNS_RESOLVE || op == MY_IP_ADDRESS) {
    // dnsResolve() and myIpAddress() are expected to return a single IP
    // address.
    cache_value = addresses.front().ToStringWithoutPort();
  } else {
    // The *Ex versions are expected to return a semi-colon separated list.
    for (AddressList::const_iterator iter = addresses.begin();
         iter != addresses.end(); ++iter) {
      if (!cache_value.empty())
        cache_value += ";";
      cache_value += iter->ToStringWithoutPort();
    }
  }

  dns_cache_[MakeDnsCacheKey(host, op)] = cache_value;
}

// static
HostResolver::RequestInfo Job::MakeDnsRequestInfo(const std::string& host,
                                                  ResolveDnsOperation op) {
  HostPortPair host_port = HostPortPair(host, 80);
  if (op == MY_IP_ADDRESS || op == MY_IP_ADDRESS_EX) {
    host_port.set_host(GetHostName());
  }

  HostResolver::RequestInfo info(host_port);
  // Flag myIpAddress requests.
  if (op == MY_IP_ADDRESS || op == MY_IP_ADDRESS_EX) {
    // TODO: Provide a RequestInfo construction mechanism that does not
    // require a hostname and sets is_my_ip_address to true instead of this.
    info.set_is_my_ip_address(true);
  }
  // The non-ex flavors are limited to IPv4 results.
  if (op == MY_IP_ADDRESS || op == DNS_RESOLVE) {
    info.set_address_family(ADDRESS_FAMILY_IPV4);
  }

  return info;
}

std::string Job::MakeDnsCacheKey(const std::string& host,
                                 ResolveDnsOperation op) {
  return base::StringPrintf("%d:%s", op, host.c_str());
}

void Job::HandleAlertOrError(bool is_alert,
                             int line_number,
                             const base::string16& message) {
  CheckIsOnWorkerThread();

  if (cancelled_.IsSet())
    return;

  if (blocking_dns_) {
    // In blocking DNS mode the events can be dispatched immediately.
    origin_runner_->PostTask(
        FROM_HERE, base::Bind(&Job::DispatchAlertOrErrorOnOriginThread, this,
                              is_alert, line_number, message));
    return;
  }

  // Otherwise in nonblocking mode, buffer all the messages until
  // the end.

  if (abandoned_)
    return;

  alerts_and_errors_byte_cost_ += sizeof(AlertOrError) + message.size() * 2;

  // If there have been lots of messages, enqueing could be expensive on
  // memory. Consider a script which does megabytes worth of alerts().
  // Avoid this by falling back to blocking mode.
  if (alerts_and_errors_byte_cost_ > kMaxAlertsAndErrorsBytes) {
    alerts_and_errors_.clear();
    ScheduleRestartWithBlockingDns();
    return;
  }

  AlertOrError entry = {is_alert, line_number, message};
  alerts_and_errors_.push_back(entry);
}

void Job::DispatchBufferedAlertsAndErrors() {
  CheckIsOnOriginThread();
  for (size_t i = 0; i < alerts_and_errors_.size(); ++i) {
    const AlertOrError& x = alerts_and_errors_[i];
    DispatchAlertOrErrorOnOriginThread(x.is_alert, x.line_number, x.message);
  }
}

void Job::DispatchAlertOrErrorOnOriginThread(bool is_alert,
                                             int line_number,
                                             const base::string16& message) {
  CheckIsOnOriginThread();

  if (cancelled_.IsSet())
    return;

  if (is_alert) {
    // -------------------
    // alert
    // -------------------
    VLOG(1) << "PAC-alert: " << message;

    bindings_->Alert(message);
  } else {
    // -------------------
    // error
    // -------------------
    if (line_number == -1)
      VLOG(1) << "PAC-error: " << message;
    else
      VLOG(1) << "PAC-error: " << "line: " << line_number << ": " << message;

    bindings_->OnError(line_number, message);
  }
}

ProxyResolverV8TracingImpl::ProxyResolverV8TracingImpl(
    std::unique_ptr<base::Thread> thread,
    std::unique_ptr<ProxyResolverV8> resolver,
    std::unique_ptr<Job::Params> job_params)
    : thread_(std::move(thread)),
      v8_resolver_(std::move(resolver)),
      job_params_(std::move(job_params)),
      num_outstanding_callbacks_(0) {
  job_params_->num_outstanding_callbacks = &num_outstanding_callbacks_;
}

ProxyResolverV8TracingImpl::~ProxyResolverV8TracingImpl() {
  // Note, all requests should have been cancelled.
  CHECK_EQ(0, num_outstanding_callbacks_);

  // Join the worker thread. See http://crbug.com/69710.
  base::ThreadRestrictions::ScopedAllowIO allow_io;
  thread_.reset();
}

void ProxyResolverV8TracingImpl::GetProxyForURL(
    const GURL& url,
    ProxyInfo* results,
    const CompletionCallback& callback,
    ProxyResolver::RequestHandle* request,
    std::unique_ptr<Bindings> bindings) {
  DCHECK(CalledOnValidThread());
  DCHECK(!callback.is_null());

  scoped_refptr<Job> job = new Job(job_params_.get(), std::move(bindings));

  if (request)
    *request = job.get();

  job->StartGetProxyForURL(url, results, callback);
}

void ProxyResolverV8TracingImpl::CancelRequest(
    ProxyResolver::RequestHandle request) {
  Job* job = reinterpret_cast<Job*>(request);
  job->Cancel();
}

LoadState ProxyResolverV8TracingImpl::GetLoadState(
    ProxyResolver::RequestHandle request) const {
  Job* job = reinterpret_cast<Job*>(request);
  return job->GetLoadState();
}

class ProxyResolverV8TracingFactoryImpl : public ProxyResolverV8TracingFactory {
 public:
  ProxyResolverV8TracingFactoryImpl();
  ~ProxyResolverV8TracingFactoryImpl() override;

  void CreateProxyResolverV8Tracing(
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings,
      std::unique_ptr<ProxyResolverV8Tracing>* resolver,
      const CompletionCallback& callback,
      std::unique_ptr<ProxyResolverFactory::Request>* request) override;

 private:
  class CreateJob;

  void RemoveJob(CreateJob* job);

  std::set<CreateJob*> jobs_;

  DISALLOW_COPY_AND_ASSIGN(ProxyResolverV8TracingFactoryImpl);
};

class ProxyResolverV8TracingFactoryImpl::CreateJob
    : public ProxyResolverFactory::Request {
 public:
  CreateJob(ProxyResolverV8TracingFactoryImpl* factory,
            std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings,
            const scoped_refptr<ProxyResolverScriptData>& pac_script,
            std::unique_ptr<ProxyResolverV8Tracing>* resolver_out,
            const CompletionCallback& callback)
      : factory_(factory),
        thread_(new base::Thread("Proxy Resolver")),
        resolver_out_(resolver_out),
        callback_(callback),
        num_outstanding_callbacks_(0) {
    // Start up the thread.
    base::Thread::Options options;
    options.timer_slack = base::TIMER_SLACK_MAXIMUM;
    CHECK(thread_->StartWithOptions(options));
    job_params_.reset(
        new Job::Params(thread_->task_runner(), &num_outstanding_callbacks_));
    create_resolver_job_ = new Job(job_params_.get(), std::move(bindings));
    create_resolver_job_->StartCreateV8Resolver(
        pac_script, &v8_resolver_,
        base::Bind(
            &ProxyResolverV8TracingFactoryImpl::CreateJob::OnV8ResolverCreated,
            base::Unretained(this)));
  }

  ~CreateJob() override {
    if (factory_) {
      factory_->RemoveJob(this);
      DCHECK(create_resolver_job_);
      create_resolver_job_->Cancel();
      StopWorkerThread();
    }
    DCHECK_EQ(0, num_outstanding_callbacks_);
  }

  void FactoryDestroyed() {
    factory_ = nullptr;
    create_resolver_job_->Cancel();
    create_resolver_job_ = nullptr;
    StopWorkerThread();
  }

 private:
  void OnV8ResolverCreated(int error) {
    DCHECK(factory_);
    if (error == OK) {
      job_params_->v8_resolver = v8_resolver_.get();
      resolver_out_->reset(new ProxyResolverV8TracingImpl(
          std::move(thread_), std::move(v8_resolver_), std::move(job_params_)));
    } else {
      StopWorkerThread();
    }

    factory_->RemoveJob(this);
    factory_ = nullptr;
    create_resolver_job_ = nullptr;
    callback_.Run(error);
  }

  void StopWorkerThread() {
    // Join the worker thread. See http://crbug.com/69710.
    base::ThreadRestrictions::ScopedAllowIO allow_io;
    thread_.reset();
  }

  ProxyResolverV8TracingFactoryImpl* factory_;
  std::unique_ptr<base::Thread> thread_;
  std::unique_ptr<Job::Params> job_params_;
  scoped_refptr<Job> create_resolver_job_;
  std::unique_ptr<ProxyResolverV8> v8_resolver_;
  std::unique_ptr<ProxyResolverV8Tracing>* resolver_out_;
  const CompletionCallback callback_;
  int num_outstanding_callbacks_;

  DISALLOW_COPY_AND_ASSIGN(CreateJob);
};

ProxyResolverV8TracingFactoryImpl::ProxyResolverV8TracingFactoryImpl() {
}

ProxyResolverV8TracingFactoryImpl::~ProxyResolverV8TracingFactoryImpl() {
  for (auto* job : jobs_) {
    job->FactoryDestroyed();
  }
}

void ProxyResolverV8TracingFactoryImpl::CreateProxyResolverV8Tracing(
    const scoped_refptr<ProxyResolverScriptData>& pac_script,
    std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings,
    std::unique_ptr<ProxyResolverV8Tracing>* resolver,
    const CompletionCallback& callback,
    std::unique_ptr<ProxyResolverFactory::Request>* request) {
  std::unique_ptr<CreateJob> job(
      new CreateJob(this, std::move(bindings), pac_script, resolver, callback));
  jobs_.insert(job.get());
  *request = std::move(job);
}

void ProxyResolverV8TracingFactoryImpl::RemoveJob(
    ProxyResolverV8TracingFactoryImpl::CreateJob* job) {
  size_t erased = jobs_.erase(job);
  DCHECK_EQ(1u, erased);
}

}  // namespace

// static
std::unique_ptr<ProxyResolverV8TracingFactory>
ProxyResolverV8TracingFactory::Create() {
  return base::WrapUnique(new ProxyResolverV8TracingFactoryImpl());
}

}  // namespace net
