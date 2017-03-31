// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_report.h"

#include <memory>
#include <string>

#include "base/time/time.h"
#include "base/values.h"
#include "url/gurl.h"

namespace net {

ReportingReport::ReportingReport(const GURL& url,
                                 const std::string& group,
                                 const std::string& type,
                                 std::unique_ptr<const base::Value> body,
                                 base::TimeTicks queued,
                                 int attempts)
    : url(url),
      group(group),
      type(type),
      body(std::move(body)),
      queued(queued),
      attempts(attempts) {}

ReportingReport::~ReportingReport() {}

}  // namespace net
