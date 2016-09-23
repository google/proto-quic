// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/multi_threaded_proxy_resolver.h"

#include <deque>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/non_thread_safe.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver.h"

namespace net {
namespace {
class Job;

// An "executor" is a job-runner for PAC requests. It encapsulates a worker
// thread and a synchronous ProxyResolver (which will be operated on said
// thread.)
class Executor : public base::RefCountedThreadSafe<Executor> {
 public:
  class Coordinator {
   public:
    virtual void OnExecutorReady(Executor* executor) = 0;

   protected:
    virtual ~Coordinator() = default;
  };

  // |coordinator| must remain valid throughout our lifetime. It is used to
  // signal when the executor is ready to receive work by calling
  // |coordinator->OnExecutorReady()|.
  // |thread_number| is an identifier used when naming the worker thread.
  Executor(Coordinator* coordinator, int thread_number);

  // Submit a job to this executor.
  void StartJob(Job* job);

  // Callback for when a job has completed running on the executor's thread.
  void OnJobCompleted(Job* job);

  // Cleanup the executor. Cancels all outstanding work, and frees the thread
  // and resolver.
  void Destroy();

  // Returns the outstanding job, or NULL.
  Job* outstanding_job() const { return outstanding_job_.get(); }

  ProxyResolver* resolver() { return resolver_.get(); }

  int thread_number() const { return thread_number_; }

  void set_resolver(std::unique_ptr<ProxyResolver> resolver) {
    resolver_ = std::move(resolver);
  }

  void set_coordinator(Coordinator* coordinator) {
    DCHECK(coordinator);
    DCHECK(coordinator_);
    coordinator_ = coordinator;
  }

 private:
  friend class base::RefCountedThreadSafe<Executor>;
  ~Executor();

  Coordinator* coordinator_;
  const int thread_number_;

  // The currently active job for this executor (either a CreateProxyResolver or
  // GetProxyForURL task).
  scoped_refptr<Job> outstanding_job_;

  // The synchronous resolver implementation.
  std::unique_ptr<ProxyResolver> resolver_;

  // The thread where |resolver_| is run on.
  // Note that declaration ordering is important here. |thread_| needs to be
  // destroyed *before* |resolver_|, in case |resolver_| is currently
  // executing on |thread_|.
  std::unique_ptr<base::Thread> thread_;
};

class MultiThreadedProxyResolver : public ProxyResolver,
                                   public Executor::Coordinator,
                                   public base::NonThreadSafe {
 public:
  // Creates an asynchronous ProxyResolver that runs requests on up to
  // |max_num_threads|.
  //
  // For each thread that is created, an accompanying synchronous ProxyResolver
  // will be provisioned using |resolver_factory|. All methods on these
  // ProxyResolvers will be called on the one thread.
  MultiThreadedProxyResolver(
      std::unique_ptr<ProxyResolverFactory> resolver_factory,
      size_t max_num_threads,
      const scoped_refptr<ProxyResolverScriptData>& script_data,
      scoped_refptr<Executor> executor);

  ~MultiThreadedProxyResolver() override;

  // ProxyResolver implementation:
  int GetProxyForURL(const GURL& url,
                     ProxyInfo* results,
                     const CompletionCallback& callback,
                     RequestHandle* request,
                     const NetLogWithSource& net_log) override;
  void CancelRequest(RequestHandle request) override;
  LoadState GetLoadState(RequestHandle request) const override;

 private:
  class GetProxyForURLJob;
  // FIFO queue of pending jobs waiting to be started.
  // TODO(eroman): Make this priority queue.
  typedef std::deque<scoped_refptr<Job>> PendingJobsQueue;
  typedef std::vector<scoped_refptr<Executor>> ExecutorList;

  // Returns an idle worker thread which is ready to receive GetProxyForURL()
  // requests. If all threads are occupied, returns NULL.
  Executor* FindIdleExecutor();

  // Creates a new worker thread, and appends it to |executors_|.
  void AddNewExecutor();

  // Starts the next job from |pending_jobs_| if possible.
  void OnExecutorReady(Executor* executor) override;

  const std::unique_ptr<ProxyResolverFactory> resolver_factory_;
  const size_t max_num_threads_;
  PendingJobsQueue pending_jobs_;
  ExecutorList executors_;
  scoped_refptr<ProxyResolverScriptData> script_data_;
};

// Job ---------------------------------------------

class Job : public base::RefCountedThreadSafe<Job> {
 public:
  // Identifies the subclass of Job (only being used for debugging purposes).
  enum Type {
    TYPE_GET_PROXY_FOR_URL,
    TYPE_CREATE_RESOLVER,
  };

  Job(Type type, const CompletionCallback& callback)
      : type_(type),
        callback_(callback),
        executor_(NULL),
        was_cancelled_(false) {
  }

  void set_executor(Executor* executor) {
    executor_ = executor;
  }

  // The "executor" is the job runner that is scheduling this job. If
  // this job has not been submitted to an executor yet, this will be
  // NULL (and we know it hasn't started yet).
  Executor* executor() {
    return executor_;
  }

  // Mark the job as having been cancelled.
  void Cancel() {
    was_cancelled_ = true;
  }

  // Returns true if Cancel() has been called.
  bool was_cancelled() const { return was_cancelled_; }

  Type type() const { return type_; }

  // Returns true if this job still has a user callback. Some jobs
  // do not have a user callback, because they were helper jobs
  // scheduled internally (for example TYPE_CREATE_RESOLVER).
  //
  // Otherwise jobs that correspond with user-initiated work will
  // have a non-null callback up until the callback is run.
  bool has_user_callback() const { return !callback_.is_null(); }

  // This method is called when the job is inserted into a wait queue
  // because no executors were ready to accept it.
  virtual void WaitingForThread() {}

  // This method is called just before the job is posted to the work thread.
  virtual void FinishedWaitingForThread() {}

  // This method is called on the worker thread to do the job's work. On
  // completion, implementors are expected to call OnJobCompleted() on
  // |origin_runner|.
  virtual void Run(
      scoped_refptr<base::SingleThreadTaskRunner> origin_runner) = 0;

 protected:
  void OnJobCompleted() {
    // |executor_| will be NULL if the executor has already been deleted.
    if (executor_)
      executor_->OnJobCompleted(this);
  }

  void RunUserCallback(int result) {
    DCHECK(has_user_callback());
    CompletionCallback callback = callback_;
    // Reset the callback so has_user_callback() will now return false.
    callback_.Reset();
    callback.Run(result);
  }

  friend class base::RefCountedThreadSafe<Job>;

  virtual ~Job() {}

 private:
  const Type type_;
  CompletionCallback callback_;
  Executor* executor_;
  bool was_cancelled_;
};

// CreateResolverJob -----------------------------------------------------------

// Runs on the worker thread to call ProxyResolverFactory::CreateProxyResolver.
class CreateResolverJob : public Job {
 public:
  CreateResolverJob(const scoped_refptr<ProxyResolverScriptData>& script_data,
                    ProxyResolverFactory* factory)
      : Job(TYPE_CREATE_RESOLVER, CompletionCallback()),
        script_data_(script_data),
        factory_(factory) {}

  // Runs on the worker thread.
  void Run(scoped_refptr<base::SingleThreadTaskRunner> origin_runner) override {
    std::unique_ptr<ProxyResolverFactory::Request> request;
    int rv = factory_->CreateProxyResolver(script_data_, &resolver_,
                                           CompletionCallback(), &request);

    DCHECK_NE(rv, ERR_IO_PENDING);
    origin_runner->PostTask(
        FROM_HERE, base::Bind(&CreateResolverJob::RequestComplete, this, rv));
  }

 protected:
  ~CreateResolverJob() override {}

 private:
  // Runs the completion callback on the origin thread.
  void RequestComplete(int result_code) {
    // The task may have been cancelled after it was started.
    if (!was_cancelled()) {
      DCHECK(executor());
      executor()->set_resolver(std::move(resolver_));
    }
    OnJobCompleted();
  }

  const scoped_refptr<ProxyResolverScriptData> script_data_;
  ProxyResolverFactory* factory_;
  std::unique_ptr<ProxyResolver> resolver_;
};

// MultiThreadedProxyResolver::GetProxyForURLJob ------------------------------

class MultiThreadedProxyResolver::GetProxyForURLJob : public Job {
 public:
  // |url|         -- the URL of the query.
  // |results|     -- the structure to fill with proxy resolve results.
  GetProxyForURLJob(const GURL& url,
                    ProxyInfo* results,
                    const CompletionCallback& callback,
                    const NetLogWithSource& net_log)
      : Job(TYPE_GET_PROXY_FOR_URL, callback),
        results_(results),
        net_log_(net_log),
        url_(url),
        was_waiting_for_thread_(false) {
    DCHECK(!callback.is_null());
  }

  NetLogWithSource* net_log() { return &net_log_; }

  void WaitingForThread() override {
    was_waiting_for_thread_ = true;
    net_log_.BeginEvent(NetLogEventType::WAITING_FOR_PROXY_RESOLVER_THREAD);
  }

  void FinishedWaitingForThread() override {
    DCHECK(executor());

    if (was_waiting_for_thread_) {
      net_log_.EndEvent(NetLogEventType::WAITING_FOR_PROXY_RESOLVER_THREAD);
    }

    net_log_.AddEvent(
        NetLogEventType::SUBMITTED_TO_RESOLVER_THREAD,
        NetLog::IntCallback("thread_number", executor()->thread_number()));
  }

  // Runs on the worker thread.
  void Run(scoped_refptr<base::SingleThreadTaskRunner> origin_runner) override {
    ProxyResolver* resolver = executor()->resolver();
    DCHECK(resolver);
    int rv = resolver->GetProxyForURL(
        url_, &results_buf_, CompletionCallback(), NULL, net_log_);
    DCHECK_NE(rv, ERR_IO_PENDING);

    origin_runner->PostTask(
        FROM_HERE, base::Bind(&GetProxyForURLJob::QueryComplete, this, rv));
  }

 protected:
  ~GetProxyForURLJob() override {}

 private:
  // Runs the completion callback on the origin thread.
  void QueryComplete(int result_code) {
    // The Job may have been cancelled after it was started.
    if (!was_cancelled()) {
      if (result_code >= OK) {  // Note: unit-tests use values > 0.
        results_->Use(results_buf_);
      }
      RunUserCallback(result_code);
    }
    OnJobCompleted();
  }

  // Must only be used on the "origin" thread.
  ProxyInfo* results_;

  // Can be used on either "origin" or worker thread.
  NetLogWithSource net_log_;
  const GURL url_;

  // Usable from within DoQuery on the worker thread.
  ProxyInfo results_buf_;

  bool was_waiting_for_thread_;
};

// Executor ----------------------------------------

Executor::Executor(Executor::Coordinator* coordinator, int thread_number)
    : coordinator_(coordinator), thread_number_(thread_number) {
  DCHECK(coordinator);
  // Start up the thread.
  thread_.reset(new base::Thread(base::StringPrintf("PAC thread #%d",
                                                    thread_number)));
  CHECK(thread_->Start());
}

void Executor::StartJob(Job* job) {
  DCHECK(!outstanding_job_.get());
  outstanding_job_ = job;

  // Run the job. Once it has completed (regardless of whether it was
  // cancelled), it will invoke OnJobCompleted() on this thread.
  job->set_executor(this);
  job->FinishedWaitingForThread();
  thread_->task_runner()->PostTask(
      FROM_HERE,
      base::Bind(&Job::Run, job, base::ThreadTaskRunnerHandle::Get()));
}

void Executor::OnJobCompleted(Job* job) {
  DCHECK_EQ(job, outstanding_job_.get());
  outstanding_job_ = NULL;
  coordinator_->OnExecutorReady(this);
}

void Executor::Destroy() {
  DCHECK(coordinator_);

  {
    // See http://crbug.com/69710.
    base::ThreadRestrictions::ScopedAllowIO allow_io;

    // Join the worker thread.
    thread_.reset();
  }

  // Cancel any outstanding job.
  if (outstanding_job_.get()) {
    outstanding_job_->Cancel();
    // Orphan the job (since this executor may be deleted soon).
    outstanding_job_->set_executor(NULL);
  }

  // It is now safe to free the ProxyResolver, since all the tasks that
  // were using it on the resolver thread have completed.
  resolver_.reset();

  // Null some stuff as a precaution.
  coordinator_ = NULL;
  outstanding_job_ = NULL;
}

Executor::~Executor() {
  // The important cleanup happens as part of Destroy(), which should always be
  // called first.
  DCHECK(!coordinator_) << "Destroy() was not called";
  DCHECK(!thread_.get());
  DCHECK(!resolver_.get());
  DCHECK(!outstanding_job_.get());
}

// MultiThreadedProxyResolver --------------------------------------------------

MultiThreadedProxyResolver::MultiThreadedProxyResolver(
    std::unique_ptr<ProxyResolverFactory> resolver_factory,
    size_t max_num_threads,
    const scoped_refptr<ProxyResolverScriptData>& script_data,
    scoped_refptr<Executor> executor)
    : resolver_factory_(std::move(resolver_factory)),
      max_num_threads_(max_num_threads),
      script_data_(script_data) {
  DCHECK(script_data_);
  executor->set_coordinator(this);
  executors_.push_back(executor);
}

MultiThreadedProxyResolver::~MultiThreadedProxyResolver() {
  DCHECK(CalledOnValidThread());
  // We will cancel all outstanding requests.
  pending_jobs_.clear();

  for (auto& executor : executors_) {
    executor->Destroy();
  }
}

int MultiThreadedProxyResolver::GetProxyForURL(
    const GURL& url,
    ProxyInfo* results,
    const CompletionCallback& callback,
    RequestHandle* request,
    const NetLogWithSource& net_log) {
  DCHECK(CalledOnValidThread());
  DCHECK(!callback.is_null());

  scoped_refptr<GetProxyForURLJob> job(
      new GetProxyForURLJob(url, results, callback, net_log));

  // Completion will be notified through |callback|, unless the caller cancels
  // the request using |request|.
  if (request)
    *request = reinterpret_cast<RequestHandle>(job.get());

  // If there is an executor that is ready to run this request, submit it!
  Executor* executor = FindIdleExecutor();
  if (executor) {
    DCHECK_EQ(0u, pending_jobs_.size());
    executor->StartJob(job.get());
    return ERR_IO_PENDING;
  }

  // Otherwise queue this request. (We will schedule it to a thread once one
  // becomes available).
  job->WaitingForThread();
  pending_jobs_.push_back(job);

  // If we haven't already reached the thread limit, provision a new thread to
  // drain the requests more quickly.
  if (executors_.size() < max_num_threads_)
    AddNewExecutor();

  return ERR_IO_PENDING;
}

void MultiThreadedProxyResolver::CancelRequest(RequestHandle req) {
  DCHECK(CalledOnValidThread());
  DCHECK(req);

  Job* job = reinterpret_cast<Job*>(req);
  DCHECK_EQ(Job::TYPE_GET_PROXY_FOR_URL, job->type());

  if (job->executor()) {
    // If the job was already submitted to the executor, just mark it
    // as cancelled so the user callback isn't run on completion.
    job->Cancel();
  } else {
    // Otherwise the job is just sitting in a queue.
    PendingJobsQueue::iterator it =
        std::find(pending_jobs_.begin(), pending_jobs_.end(), job);
    DCHECK(it != pending_jobs_.end());
    pending_jobs_.erase(it);
  }
}

LoadState MultiThreadedProxyResolver::GetLoadState(RequestHandle req) const {
  DCHECK(CalledOnValidThread());
  DCHECK(req);
  return LOAD_STATE_RESOLVING_PROXY_FOR_URL;
}

Executor* MultiThreadedProxyResolver::FindIdleExecutor() {
  DCHECK(CalledOnValidThread());
  for (ExecutorList::iterator it = executors_.begin();
       it != executors_.end(); ++it) {
    Executor* executor = it->get();
    if (!executor->outstanding_job())
      return executor;
  }
  return NULL;
}

void MultiThreadedProxyResolver::AddNewExecutor() {
  DCHECK(CalledOnValidThread());
  DCHECK_LT(executors_.size(), max_num_threads_);
  // The "thread number" is used to give the thread a unique name.
  int thread_number = executors_.size();
  Executor* executor = new Executor(this, thread_number);
  executor->StartJob(
      new CreateResolverJob(script_data_, resolver_factory_.get()));
  executors_.push_back(make_scoped_refptr(executor));
}

void MultiThreadedProxyResolver::OnExecutorReady(Executor* executor) {
  DCHECK(CalledOnValidThread());
  if (pending_jobs_.empty())
    return;

  // Get the next job to process (FIFO). Transfer it from the pending queue
  // to the executor.
  scoped_refptr<Job> job = pending_jobs_.front();
  pending_jobs_.pop_front();
  executor->StartJob(job.get());
}

}  // namespace

class MultiThreadedProxyResolverFactory::Job
    : public ProxyResolverFactory::Request,
      public Executor::Coordinator {
 public:
  Job(MultiThreadedProxyResolverFactory* factory,
      const scoped_refptr<ProxyResolverScriptData>& script_data,
      std::unique_ptr<ProxyResolver>* resolver,
      std::unique_ptr<ProxyResolverFactory> resolver_factory,
      size_t max_num_threads,
      const CompletionCallback& callback)
      : factory_(factory),
        resolver_out_(resolver),
        resolver_factory_(std::move(resolver_factory)),
        max_num_threads_(max_num_threads),
        script_data_(script_data),
        executor_(new Executor(this, 0)),
        callback_(callback) {
    executor_->StartJob(
        new CreateResolverJob(script_data_, resolver_factory_.get()));
  }

  ~Job() override {
    if (factory_) {
      executor_->Destroy();
      factory_->RemoveJob(this);
    }
  }

  void FactoryDestroyed() {
    executor_->Destroy();
    executor_ = nullptr;
    factory_ = nullptr;
  }

 private:
  void OnExecutorReady(Executor* executor) override {
    int error = OK;
    if (executor->resolver()) {
      resolver_out_->reset(new MultiThreadedProxyResolver(
          std::move(resolver_factory_), max_num_threads_,
          std::move(script_data_), executor_));
    } else {
      error = ERR_PAC_SCRIPT_FAILED;
      executor_->Destroy();
    }
    factory_->RemoveJob(this);
    factory_ = nullptr;
    callback_.Run(error);
  }

  MultiThreadedProxyResolverFactory* factory_;
  std::unique_ptr<ProxyResolver>* const resolver_out_;
  std::unique_ptr<ProxyResolverFactory> resolver_factory_;
  const size_t max_num_threads_;
  scoped_refptr<ProxyResolverScriptData> script_data_;
  scoped_refptr<Executor> executor_;
  const CompletionCallback callback_;
};

MultiThreadedProxyResolverFactory::MultiThreadedProxyResolverFactory(
    size_t max_num_threads,
    bool factory_expects_bytes)
    : ProxyResolverFactory(factory_expects_bytes),
      max_num_threads_(max_num_threads) {
  DCHECK_GE(max_num_threads, 1u);
}

MultiThreadedProxyResolverFactory::~MultiThreadedProxyResolverFactory() {
  for (auto* job : jobs_) {
    job->FactoryDestroyed();
  }
}

int MultiThreadedProxyResolverFactory::CreateProxyResolver(
    const scoped_refptr<ProxyResolverScriptData>& pac_script,
    std::unique_ptr<ProxyResolver>* resolver,
    const CompletionCallback& callback,
    std::unique_ptr<Request>* request) {
  std::unique_ptr<Job> job(new Job(this, pac_script, resolver,
                                   CreateProxyResolverFactory(),
                                   max_num_threads_, callback));
  jobs_.insert(job.get());
  *request = std::move(job);
  return ERR_IO_PENDING;
}

void MultiThreadedProxyResolverFactory::RemoveJob(
    MultiThreadedProxyResolverFactory::Job* job) {
  size_t erased = jobs_.erase(job);
  DCHECK_EQ(1u, erased);
}

}  // namespace net
