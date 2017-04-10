// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_REPORTING_REPORTING_REPORT_H_
#define NET_REPORTING_REPORTING_REPORT_H_

#include <memory>
#include <string>

#include "base/time/time.h"
#include "net/base/net_export.h"
#include "url/gurl.h"

namespace base {
class Value;
}  // namespace base

namespace net {

// An undelivered report.
struct NET_EXPORT ReportingReport {
 public:
  ReportingReport(const GURL& url,
                  const std::string& group,
                  const std::string& type,
                  std::unique_ptr<const base::Value> body,
                  base::TimeTicks queued,
                  int attempts);
  ~ReportingReport();

  // The URL of the document that triggered the report. (Included in the
  // delivered report.)
  GURL url;

  // The endpoint group that should be used to deliver the report. (Not included
  // in the delivered report.)
  std::string group;

  // The type of the report. (Included in the delivered report.)
  std::string type;

  // The body of the report. (Included in the delivered report.)
  std::unique_ptr<const base::Value> body;

  // When the report was queued. (Included in the delivered report as an age
  // relative to the time of the delivery attempt.)
  base::TimeTicks queued;

  // The number of delivery attempts made so far, not including an active
  // attempt. (Not included in the delivered report.)
  int attempts = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(ReportingReport);
};

}  // namespace net

#endif  // NET_REPORTING_REPORTING_REPORT_H_
