// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_garbage_collector.h"

#include <utility>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_observer.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_report.h"

namespace net {

namespace {

class ReportingGarbageCollectorImpl : public ReportingGarbageCollector,
                                      public ReportingObserver {
 public:
  ReportingGarbageCollectorImpl(ReportingContext* context)
      : context_(context), timer_(base::MakeUnique<base::OneShotTimer>()) {
    context_->AddObserver(this);
  }

  // ReportingGarbageCollector implementation:

  ~ReportingGarbageCollectorImpl() override {
    context_->RemoveObserver(this);
  }

  void SetTimerForTesting(std::unique_ptr<base::Timer> timer) override {
    timer_ = std::move(timer);
  }

  // ReportingObserver implementation:
  void OnCacheUpdated() override {
    if (timer_->IsRunning())
      return;

    timer_->Start(FROM_HERE, context_->policy().garbage_collection_interval,
                  base::Bind(&ReportingGarbageCollectorImpl::CollectGarbage,
                             base::Unretained(this)));
  }

 private:
  void CollectGarbage() {
    base::TimeTicks now = context_->tick_clock()->NowTicks();
    const ReportingPolicy& policy = context_->policy();

    std::vector<const ReportingReport*> all_reports;
    context_->cache()->GetReports(&all_reports);

    std::vector<const ReportingReport*> reports_to_remove;
    for (const ReportingReport* report : all_reports) {
      if (now - report->queued >= policy.max_report_age ||
          report->attempts >= policy.max_report_attempts) {
        reports_to_remove.push_back(report);
      }
    }

    // Don't restart the timer on the garbage collector's own updates.
    context_->RemoveObserver(this);
    context_->cache()->RemoveReports(reports_to_remove);
    context_->AddObserver(this);
  }

  ReportingContext* context_;
  std::unique_ptr<base::Timer> timer_;
};

}  // namespace

// static
std::unique_ptr<ReportingGarbageCollector> ReportingGarbageCollector::Create(
    ReportingContext* context) {
  return base::MakeUnique<ReportingGarbageCollectorImpl>(context);
}

ReportingGarbageCollector::~ReportingGarbageCollector() {}

}  // namespace net
