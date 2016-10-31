// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_throttle_manager.h"

#include "base/logging.h"
#include "net/base/priority_queue.h"

namespace net {

namespace {

class NetworkThrottleManagerImpl : public NetworkThrottleManager {
 public:
  class ThrottleImpl : public NetworkThrottleManager::Throttle {
   public:
    using QueuePointer = PriorityQueue<ThrottleImpl*>::Pointer;

    // Caller must arrange that |*delegate| and |*throttler| outlive
    // the ThrottleImpl class.
    ThrottleImpl(bool throttled,
                 RequestPriority priority,
                 ThrottleDelegate* delegate,
                 NetworkThrottleManagerImpl* throttler);

    ~ThrottleImpl() override;

    // Throttle
    bool IsThrottled() const override;
    void SetPriority(RequestPriority priority) override;

    QueuePointer queue_pointer() const { return queue_pointer_; }
    void set_queue_pointer(const QueuePointer& pointer) {
      queue_pointer_ = pointer;
    }

    // Note that this call calls the delegate, and hence
    // may result in re-entrant calls into the throttler or
    // ThrottleImpl.  The throttler should not rely on
    // any state other than its own existence being persistent
    // across this call.
    void NotifyUnthrottled();

   private:
    bool throttled_;
    ThrottleDelegate* const delegate_;
    PriorityQueue<ThrottleImpl*>::Pointer queue_pointer_;

    NetworkThrottleManagerImpl* const throttler_;

    DISALLOW_COPY_AND_ASSIGN(ThrottleImpl);
  };

  NetworkThrottleManagerImpl();
  ~NetworkThrottleManagerImpl() override;

  std::unique_ptr<Throttle> CreateThrottle(ThrottleDelegate* delegate,
                                           RequestPriority priority,
                                           bool ignore_limits) override;

 private:
  void OnStreamPriorityChanged(ThrottleImpl* throttle,
                               RequestPriority new_priority);
  void OnStreamDestroyed(ThrottleImpl* throttle);

  PriorityQueue<ThrottleImpl*> priority_queue_;

  DISALLOW_COPY_AND_ASSIGN(NetworkThrottleManagerImpl);
};

// Currently this is a null implementation that does no throttling;
// all entries are created in the unthrottled state, and no throttle state
// change notifications are transmitted.

NetworkThrottleManagerImpl::ThrottleImpl::ThrottleImpl(
    bool throttled,
    RequestPriority priority,
    NetworkThrottleManager::ThrottleDelegate* delegate,
    NetworkThrottleManagerImpl* throttler)
    : throttled_(throttled), delegate_(delegate), throttler_(throttler) {
  DCHECK(delegate);
}

NetworkThrottleManagerImpl::ThrottleImpl::~ThrottleImpl() {
  throttler_->OnStreamDestroyed(this);
}

void NetworkThrottleManagerImpl::ThrottleImpl::SetPriority(
    RequestPriority priority) {
  throttler_->OnStreamPriorityChanged(this, priority);
}

bool NetworkThrottleManagerImpl::ThrottleImpl::IsThrottled() const {
  return throttled_;
}

void NetworkThrottleManagerImpl::ThrottleImpl::NotifyUnthrottled() {
  // This methods should only be called once, and only if the
  // current state is throttled.
  DCHECK(throttled_);
  throttled_ = false;
  delegate_->OnThrottleStateChanged();
}

NetworkThrottleManagerImpl::NetworkThrottleManagerImpl()
    : priority_queue_(MAXIMUM_PRIORITY + 1) {}

NetworkThrottleManagerImpl::~NetworkThrottleManagerImpl() {}

std::unique_ptr<NetworkThrottleManager::Throttle>
NetworkThrottleManagerImpl::CreateThrottle(
    NetworkThrottleManager::ThrottleDelegate* delegate,
    RequestPriority priority,
    bool ignore_limits) {
  std::unique_ptr<NetworkThrottleManagerImpl::ThrottleImpl> stream(
      new ThrottleImpl(false, priority, delegate, this));

  stream->set_queue_pointer(priority_queue_.Insert(stream.get(), priority));

  return std::move(stream);
}

void NetworkThrottleManagerImpl::OnStreamPriorityChanged(
    NetworkThrottleManagerImpl::ThrottleImpl* stream,
    RequestPriority new_priority) {
  priority_queue_.Erase(stream->queue_pointer());
  stream->set_queue_pointer(priority_queue_.Insert(stream, new_priority));
}

void NetworkThrottleManagerImpl::OnStreamDestroyed(ThrottleImpl* stream) {
  priority_queue_.Erase(stream->queue_pointer());
}

}  // namespace

// static
std::unique_ptr<NetworkThrottleManager>
NetworkThrottleManager::CreateThrottler() {
  return std::unique_ptr<NetworkThrottleManager>(
      new NetworkThrottleManagerImpl);
}

}  // namespace net
