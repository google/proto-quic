// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_context.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/observer_list.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/time/default_tick_clock.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "net/base/backoff_entry.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_delegate.h"
#include "net/reporting/reporting_delivery_agent.h"
#include "net/reporting/reporting_endpoint_manager.h"
#include "net/reporting/reporting_garbage_collector.h"
#include "net/reporting/reporting_network_change_observer.h"
#include "net/reporting/reporting_observer.h"
#include "net/reporting/reporting_persister.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_uploader.h"

namespace net {

class URLRequestContext;

namespace {

class ReportingContextImpl : public ReportingContext {
 public:
  ReportingContextImpl(const ReportingPolicy& policy,
                       std::unique_ptr<ReportingDelegate> delegate,
                       URLRequestContext* request_context)
      : ReportingContext(policy,
                         std::move(delegate),
                         base::MakeUnique<base::DefaultClock>(),
                         base::MakeUnique<base::DefaultTickClock>(),
                         ReportingUploader::Create(request_context)) {}
};

}  // namespace

// static
std::unique_ptr<ReportingContext> ReportingContext::Create(
    const ReportingPolicy& policy,
    std::unique_ptr<ReportingDelegate> delegate,
    URLRequestContext* request_context) {
  return base::MakeUnique<ReportingContextImpl>(policy, std::move(delegate),
                                                request_context);
}

ReportingContext::~ReportingContext() {}

void ReportingContext::Initialize() {
  DCHECK(!initialized_);

  // This order isn't *critical*, but things will work better with it in this
  // order: with the DeliveryAgent after the Persister, it can schedule delivery
  // of persisted reports instead of waiting for a new one to be generated, and
  // with the GarbageCollector in between, it won't bother scheduling delivery
  // of reports that should be discarded instead.
  persister_->Initialize();
  garbage_collector_->Initialize();
  delivery_agent_->Initialize();

  initialized_ = true;
}

void ReportingContext::AddObserver(ReportingObserver* observer) {
  DCHECK(!observers_.HasObserver(observer));
  observers_.AddObserver(observer);
}

void ReportingContext::RemoveObserver(ReportingObserver* observer) {
  DCHECK(observers_.HasObserver(observer));
  observers_.RemoveObserver(observer);
}

void ReportingContext::NotifyCacheUpdated() {
  if (!initialized_)
    return;

  for (auto& observer : observers_)
    observer.OnCacheUpdated();
}

ReportingContext::ReportingContext(const ReportingPolicy& policy,
                                   std::unique_ptr<ReportingDelegate> delegate,
                                   std::unique_ptr<base::Clock> clock,
                                   std::unique_ptr<base::TickClock> tick_clock,
                                   std::unique_ptr<ReportingUploader> uploader)
    : policy_(policy),
      delegate_(std::move(delegate)),
      clock_(std::move(clock)),
      tick_clock_(std::move(tick_clock)),
      uploader_(std::move(uploader)),
      initialized_(false),
      cache_(base::MakeUnique<ReportingCache>(this)),
      endpoint_manager_(base::MakeUnique<ReportingEndpointManager>(this)),
      delivery_agent_(ReportingDeliveryAgent::Create(this)),
      persister_(ReportingPersister::Create(this)),
      garbage_collector_(ReportingGarbageCollector::Create(this)),
      network_change_observer_(ReportingNetworkChangeObserver::Create(this)) {}

}  // namespace net
