// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_service.h"

#include <memory>
#include <string>

#include "base/memory/ptr_util.h"
#include "base/time/tick_clock.h"
#include "base/values.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_service.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

class ReportingServiceTest : public ::testing::Test {
 protected:
  const GURL kUrl_ = GURL("https://origin/path");
  const url::Origin kOrigin_ = url::Origin(kUrl_);
  const GURL kEndpoint_ = GURL("https://endpoint/");
  const std::string kGroup_ = "group";
  const std::string kType_ = "type";

  ReportingServiceTest()
      : context_(new TestReportingContext(ReportingPolicy())),
        service_(
            ReportingService::CreateForTesting(base::WrapUnique(context_))) {}

  TestReportingContext* context() { return context_; }
  ReportingService* service() { return service_.get(); }

 private:
  TestReportingContext* context_;
  std::unique_ptr<ReportingService> service_;
};

TEST_F(ReportingServiceTest, QueueReport) {
  service()->QueueReport(kUrl_, kGroup_, kType_,
                         base::MakeUnique<base::DictionaryValue>());

  std::vector<const ReportingReport*> reports;
  context()->cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_EQ(kUrl_, reports[0]->url);
  EXPECT_EQ(kGroup_, reports[0]->group);
  EXPECT_EQ(kType_, reports[0]->type);
}

TEST_F(ReportingServiceTest, ProcessHeader) {
  service()->ProcessHeader(kUrl_, "{\"url\":\"" + kEndpoint_.spec() +
                                      "\","
                                      "\"group\":\"" +
                                      kGroup_ +
                                      "\","
                                      "\"max-age\":86400}");

  const ReportingClient* client =
      FindClientInCache(context()->cache(), kOrigin_, kEndpoint_);
  ASSERT_TRUE(client != nullptr);
  EXPECT_EQ(kOrigin_, client->origin);
  EXPECT_EQ(kEndpoint_, client->endpoint);
  EXPECT_EQ(ReportingClient::Subdomains::EXCLUDE, client->subdomains);
  EXPECT_EQ(kGroup_, client->group);
  EXPECT_EQ(context()->tick_clock()->NowTicks() + base::TimeDelta::FromDays(1),
            client->expires);
}

}  // namespace
}  // namespace net
