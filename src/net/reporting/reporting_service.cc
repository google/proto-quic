// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_service.h"

#include <memory>

#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_delegate.h"
#include "net/reporting/reporting_header_parser.h"
#include "url/gurl.h"

namespace net {

namespace {

class ReportingServiceImpl : public ReportingService {
 public:
  ReportingServiceImpl(std::unique_ptr<ReportingContext> context)
      : context_(std::move(context)) {}

  ~ReportingServiceImpl() override {}

  void QueueReport(const GURL& url,
                   const std::string& group,
                   const std::string& type,
                   std::unique_ptr<const base::Value> body) override {
    context_->cache()->AddReport(url, group, type, std::move(body),
                                 context_->tick_clock()->NowTicks(), 0);
  }

  void ProcessHeader(const GURL& url,
                     const std::string& header_value) override {
    ReportingHeaderParser::ParseHeader(context_.get(), url, header_value);
  }

 private:
  std::unique_ptr<ReportingContext> context_;

  DISALLOW_COPY_AND_ASSIGN(ReportingServiceImpl);
};

}  // namespace

ReportingService::~ReportingService() {}

// static
std::unique_ptr<ReportingService> ReportingService::Create(
    const ReportingPolicy& policy,
    URLRequestContext* request_context,
    std::unique_ptr<ReportingDelegate> delegate) {
  return base::MakeUnique<ReportingServiceImpl>(
      ReportingContext::Create(policy, std::move(delegate), request_context));
}

// static
std::unique_ptr<ReportingService> ReportingService::CreateForTesting(
    std::unique_ptr<ReportingContext> reporting_context) {
  return base::MakeUnique<ReportingServiceImpl>(std::move(reporting_context));
}

}  // namespace net
