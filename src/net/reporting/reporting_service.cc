// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_service.h"

#include <memory>

#include "base/bind.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/reporting/reporting_browsing_data_remover.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_header_parser.h"
#include "net/reporting/reporting_persister.h"
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

  void RemoveBrowsingData(
      int data_type_mask,
      base::Callback<bool(const GURL&)> origin_filter) override {
    context_->browsing_data_remover()->RemoveBrowsingData(data_type_mask,
                                                          origin_filter);
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
    URLRequestContext* request_context) {
  return base::MakeUnique<ReportingServiceImpl>(
      ReportingContext::Create(policy, request_context));
}

// static
std::unique_ptr<ReportingService> ReportingService::CreateForTesting(
    std::unique_ptr<ReportingContext> reporting_context) {
  return base::MakeUnique<ReportingServiceImpl>(std::move(reporting_context));
}

}  // namespace net
