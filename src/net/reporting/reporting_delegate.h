// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_DELEGATE_H_
#define NET_REPORTING_REPORTING_DELEGATE_H_

#include <memory>

#include "base/macros.h"
#include "net/base/net_export.h"

namespace base {
class Value;
}  // namespace base

namespace net {

// Delegate for things that the Reporting system can't do by itself, like
// persisting data across embedder restarts.
class NET_EXPORT ReportingDelegate {
 public:
  virtual ~ReportingDelegate();

  // Gets previously persisted data, if any is available. Returns a null pointer
  // if no data is available. Can be called any number of times.
  virtual std::unique_ptr<const base::Value> GetPersistedData() = 0;

  // Sets data to be persisted across embedder restarts. Ideally, this data will
  // be returned by any future calls to GetPersistedData() in this or future
  // sessions (until newer data is persisted), but no guarantee is made, since
  // the underlying persistence mechanism may or may not be reliable.
  virtual void PersistData(
      std::unique_ptr<const base::Value> persisted_data) = 0;

 protected:
  ReportingDelegate();

 private:
  DISALLOW_COPY_AND_ASSIGN(ReportingDelegate);
};

}  // namespace net

#endif  // NET_REPORTING_REPORTING_DELEGATE_H_
