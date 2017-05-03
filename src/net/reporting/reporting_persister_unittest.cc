// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_persister.h"

#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "base/timer/mock_timer.h"
#include "base/values.h"
#include "net/base/test_completion_callback.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

class ReportingPersisterTest : public ReportingTestBase {
 protected:
  const GURL kUrl_ = GURL("https://origin/path");
  const url::Origin kOrigin_ = url::Origin(kUrl_);
  const GURL kEndpoint_ = GURL("https://endpoint/");
  const std::string kGroup_ = "group";
  const std::string kType_ = "default";
};

// Disabled because the Persister has no persistence layer to use yet.
TEST_F(ReportingPersisterTest, DISABLED_Test) {
  ReportingPolicy policy;
  policy.persist_reports_across_restarts = true;
  policy.persist_clients_across_restarts = true;
  // Make sure reports don't expire on our simulated restart.
  policy.max_report_age = base::TimeDelta::FromDays(30);
  UsePolicy(policy);

  static const int kAttempts = 3;

  base::DictionaryValue body;
  body.SetString("key", "value");

  cache()->AddReport(kUrl_, kGroup_, kType_, body.CreateDeepCopy(),
                     tick_clock()->NowTicks(), kAttempts);
  cache()->SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                     kGroup_,
                     tick_clock()->NowTicks() + base::TimeDelta::FromDays(1));

  // TODO: Actually save data, once it's possible.

  SimulateRestart(/* delta= */ base::TimeDelta::FromHours(1),
                  /* delta_ticks= */ base::TimeDelta::FromHours(-3));

  // TODO: Actually load data, once it's possible.

  std::vector<const ReportingReport*> reports;
  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_EQ(kUrl_, reports[0]->url);
  EXPECT_EQ(kGroup_, reports[0]->group);
  EXPECT_EQ(kType_, reports[0]->type);
  EXPECT_TRUE(base::Value::Equals(&body, reports[0]->body.get()));
  EXPECT_EQ(tick_clock()->NowTicks() - base::TimeDelta::FromHours(1),
            reports[0]->queued);
  EXPECT_EQ(kAttempts, reports[0]->attempts);

  const ReportingClient* client =
      FindClientInCache(cache(), kOrigin_, kEndpoint_);
  ASSERT_TRUE(client);
  EXPECT_EQ(ReportingClient::Subdomains::EXCLUDE, client->subdomains);
  EXPECT_EQ(kGroup_, client->group);
  EXPECT_EQ(tick_clock()->NowTicks() + base::TimeDelta::FromDays(1) -
                base::TimeDelta::FromHours(1),
            client->expires);
}

// TODO(juliatuttle): Test asynchronous behavior.

}  // namespace
}  // namespace net
