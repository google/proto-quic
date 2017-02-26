// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/polling_proxy_config_service.h"

#include <memory>

#include "base/bind.h"
#include "base/location.h"
#include "base/observer_list.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/lock.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/proxy/proxy_config.h"

namespace net {

// Reference-counted wrapper that does all the work (needs to be
// reference-counted since we post tasks between threads; may outlive
// the parent PollingProxyConfigService).
class PollingProxyConfigService::Core
    : public base::RefCountedThreadSafe<PollingProxyConfigService::Core> {
 public:
  Core(base::TimeDelta poll_interval, GetConfigFunction get_config_func)
      : get_config_func_(get_config_func),
        poll_interval_(poll_interval),
        have_initialized_origin_runner_(false),
        has_config_(false),
        poll_task_outstanding_(false),
        poll_task_queued_(false) {}

  // Called when the parent PollingProxyConfigService is destroyed
  // (observers should not be called past this point).
  void Orphan() {
    base::AutoLock l(lock_);
    origin_task_runner_ = NULL;
  }

  bool GetLatestProxyConfig(ProxyConfig* config) {
    LazyInitializeOriginLoop();
    DCHECK(origin_task_runner_->BelongsToCurrentThread());

    OnLazyPoll();

    // If we have already retrieved the proxy settings (on worker thread)
    // then return what we last saw.
    if (has_config_) {
      *config = last_config_;
      return true;
    }
    return false;
  }

  void AddObserver(Observer* observer) {
    LazyInitializeOriginLoop();
    DCHECK(origin_task_runner_->BelongsToCurrentThread());
    observers_.AddObserver(observer);
  }

  void RemoveObserver(Observer* observer) {
    DCHECK(origin_task_runner_->BelongsToCurrentThread());
    observers_.RemoveObserver(observer);
  }

  // Check for a new configuration if enough time has elapsed.
  void OnLazyPoll() {
    LazyInitializeOriginLoop();
    DCHECK(origin_task_runner_->BelongsToCurrentThread());

    if (last_poll_time_.is_null() ||
        (base::TimeTicks::Now() - last_poll_time_) > poll_interval_) {
      CheckForChangesNow();
    }
  }

  void CheckForChangesNow() {
    LazyInitializeOriginLoop();
    DCHECK(origin_task_runner_->BelongsToCurrentThread());

    if (poll_task_outstanding_) {
      // Only allow one task to be outstanding at a time. If we get a poll
      // request while we are busy, we will defer it until the current poll
      // completes.
      poll_task_queued_ = true;
      return;
    }

    last_poll_time_ = base::TimeTicks::Now();
    poll_task_outstanding_ = true;
    poll_task_queued_ = false;
    base::PostTaskWithTraits(
        FROM_HERE, base::TaskTraits().MayBlock().WithShutdownBehavior(
                       base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN),
        base::Bind(&Core::PollAsync, this, get_config_func_));
  }

 private:
  friend class base::RefCountedThreadSafe<Core>;
  ~Core() {}

  void PollAsync(GetConfigFunction func) {
    ProxyConfig config;
    func(&config);

    base::AutoLock l(lock_);
    if (origin_task_runner_.get()) {
      origin_task_runner_->PostTask(
          FROM_HERE, base::Bind(&Core::GetConfigCompleted, this, config));
    }
  }

  // Called after the worker thread has finished retrieving a configuration.
  void GetConfigCompleted(const ProxyConfig& config) {
    DCHECK(poll_task_outstanding_);
    poll_task_outstanding_ = false;

    if (!origin_task_runner_.get())
      return;  // Was orphaned (parent has already been destroyed).

    DCHECK(origin_task_runner_->BelongsToCurrentThread());

    if (!has_config_ || !last_config_.Equals(config)) {
      // If the configuration has changed, notify the observers.
      has_config_ = true;
      last_config_ = config;
      for (auto& observer : observers_)
        observer.OnProxyConfigChanged(config, ProxyConfigService::CONFIG_VALID);
    }

    if (poll_task_queued_)
      CheckForChangesNow();
  }

  void LazyInitializeOriginLoop() {
    // TODO(eroman): Really this should be done in the constructor, but right
    //               now chrome is constructing the ProxyConfigService on the
    //               UI thread so we can't cache the IO thread for the purpose
    //               of DCHECKs until the first call is made.
    if (!have_initialized_origin_runner_) {
      origin_task_runner_ = base::ThreadTaskRunnerHandle::Get();
      have_initialized_origin_runner_ = true;
    }
  }

  GetConfigFunction get_config_func_;
  base::ObserverList<Observer> observers_;
  ProxyConfig last_config_;
  base::TimeTicks last_poll_time_;
  base::TimeDelta poll_interval_;

  base::Lock lock_;
  scoped_refptr<base::SingleThreadTaskRunner> origin_task_runner_;

  bool have_initialized_origin_runner_;
  bool has_config_;
  bool poll_task_outstanding_;
  bool poll_task_queued_;
};

void PollingProxyConfigService::AddObserver(Observer* observer) {
  core_->AddObserver(observer);
}

void PollingProxyConfigService::RemoveObserver(Observer* observer) {
  core_->RemoveObserver(observer);
}

ProxyConfigService::ConfigAvailability
    PollingProxyConfigService::GetLatestProxyConfig(ProxyConfig* config) {
  return core_->GetLatestProxyConfig(config) ? CONFIG_VALID : CONFIG_PENDING;
}

void PollingProxyConfigService::OnLazyPoll() {
  core_->OnLazyPoll();
}

PollingProxyConfigService::PollingProxyConfigService(
    base::TimeDelta poll_interval,
    GetConfigFunction get_config_func)
    : core_(new Core(poll_interval, get_config_func)) {
}

PollingProxyConfigService::~PollingProxyConfigService() {
  core_->Orphan();
}

void PollingProxyConfigService::CheckForChangesNow() {
  core_->CheckForChangesNow();
}

}  // namespace net
