// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_network_change_observer.h"

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/values.h"
#include "net/base/network_change_notifier.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

class ReportingNetworkChangeObserverTest : public ReportingTestBase {
 protected:
  void SimulateNetworkChange() {
    // TODO: Need to SetTestNotificationsOnly(true) to keep things from flaking,
    // but have to figure out how to do that before NCN is created or how to
    // recreate NCN.
    NetworkChangeNotifier::NotifyObserversOfNetworkChangeForTests(
        NetworkChangeNotifier::CONNECTION_NONE);
    base::RunLoop().RunUntilIdle();
    NetworkChangeNotifier::NotifyObserversOfNetworkChangeForTests(
        NetworkChangeNotifier::CONNECTION_WIFI);
    base::RunLoop().RunUntilIdle();
  }

  size_t report_count() {
    std::vector<const ReportingReport*> reports;
    cache()->GetReports(&reports);
    return reports.size();
  }

  size_t client_count() {
    std::vector<const ReportingClient*> clients;
    cache()->GetClients(&clients);
    return clients.size();
  }

  const GURL kUrl_ = GURL("https://origin/path");
  const url::Origin kOrigin_ = url::Origin(kUrl_);
  const GURL kEndpoint_ = GURL("https://endpoint/");
  const std::string kGroup_ = "group";
  const std::string kType_ = "default";
};

TEST_F(ReportingNetworkChangeObserverTest, ClearNothing) {
  ReportingPolicy new_policy = policy();
  new_policy.clear_reports_on_network_changes = false;
  new_policy.clear_clients_on_network_changes = false;
  UsePolicy(new_policy);

  cache()->AddReport(kUrl_, kGroup_, kType_,
                     base::MakeUnique<base::DictionaryValue>(),
                     tick_clock()->NowTicks(), 0);
  cache()->SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                     kGroup_,
                     tick_clock()->NowTicks() + base::TimeDelta::FromDays(7));
  ASSERT_EQ(1u, report_count());
  ASSERT_EQ(1u, client_count());

  SimulateNetworkChange();

  EXPECT_EQ(1u, report_count());
  EXPECT_EQ(1u, client_count());
}

TEST_F(ReportingNetworkChangeObserverTest, ClearReports) {
  ReportingPolicy new_policy = policy();
  new_policy.clear_reports_on_network_changes = true;
  new_policy.clear_clients_on_network_changes = false;
  UsePolicy(new_policy);

  cache()->AddReport(kUrl_, kGroup_, kType_,
                     base::MakeUnique<base::DictionaryValue>(),
                     tick_clock()->NowTicks(), 0);
  cache()->SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                     kGroup_,
                     tick_clock()->NowTicks() + base::TimeDelta::FromDays(7));
  ASSERT_EQ(1u, report_count());
  ASSERT_EQ(1u, client_count());

  SimulateNetworkChange();

  EXPECT_EQ(0u, report_count());
  EXPECT_EQ(1u, client_count());
}

TEST_F(ReportingNetworkChangeObserverTest, ClearClients) {
  ReportingPolicy new_policy = policy();
  new_policy.clear_reports_on_network_changes = false;
  new_policy.clear_clients_on_network_changes = true;
  UsePolicy(new_policy);

  cache()->AddReport(kUrl_, kGroup_, kType_,
                     base::MakeUnique<base::DictionaryValue>(),
                     tick_clock()->NowTicks(), 0);
  cache()->SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                     kGroup_,
                     tick_clock()->NowTicks() + base::TimeDelta::FromDays(7));
  ASSERT_EQ(1u, report_count());
  ASSERT_EQ(1u, client_count());

  SimulateNetworkChange();

  EXPECT_EQ(1u, report_count());
  EXPECT_EQ(0u, client_count());
}

TEST_F(ReportingNetworkChangeObserverTest, ClearReportsAndClients) {
  ReportingPolicy new_policy = policy();
  new_policy.clear_reports_on_network_changes = true;
  new_policy.clear_clients_on_network_changes = true;
  UsePolicy(new_policy);

  cache()->AddReport(kUrl_, kGroup_, kType_,
                     base::MakeUnique<base::DictionaryValue>(),
                     tick_clock()->NowTicks(), 0);
  cache()->SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                     kGroup_,
                     tick_clock()->NowTicks() + base::TimeDelta::FromDays(7));
  ASSERT_EQ(1u, report_count());
  ASSERT_EQ(1u, client_count());

  SimulateNetworkChange();

  EXPECT_EQ(0u, report_count());
  EXPECT_EQ(0u, client_count());
}

}  // namespace
}  // namespace net
