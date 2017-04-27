// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_PERSISTER_H_
#define NET_REPORTING_REPORTING_PERSISTER_H_

#include <memory>

#include "net/base/net_export.h"

namespace base {
class Timer;
}  // namespace base

namespace net {

class ReportingContext;

// Periodically persists the state of the Reporting system to (reasonably)
// stable storage using the methods provided by the ReportingDelegate.
class NET_EXPORT ReportingPersister {
 public:
  // Creates a ReportingPersister. |context| must outlive the persister.
  static std::unique_ptr<ReportingPersister> Create(ReportingContext* context);

  virtual ~ReportingPersister();

  // Initializes the Persister, which deserializes any previously-persisted data
  // that is available through the Context's Delegate.
  virtual void Initialize() = 0;

  // Replaces the internal Timer used for scheduling writes to stable storage
  // with a caller-specified one so that unittests can provide a MockTimer.
  virtual void SetTimerForTesting(std::unique_ptr<base::Timer> timer) = 0;
};

}  // namespace net

#endif  // NET_REPORTING_REPORTING_PERSISTER_H_
