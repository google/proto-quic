// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_cache.h"

#include <string>

#include "base/memory/ptr_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

class ReportingCacheTest : public ::testing::Test {
 protected:
  const GURL kUrl1_ = GURL("https://origin1/path");
  const url::Origin kOrigin1_ = url::Origin(GURL("https://origin1/"));
  const url::Origin kOrigin2_ = url::Origin(GURL("https://origin2/"));
  const GURL kEndpoint1_ = GURL("https://endpoint1/");
  const GURL kEndpoint2_ = GURL("https://endpoint2/");
  const std::string kGroup1_ = "group1";
  const std::string kGroup2_ = "group2";
  const std::string kType_ = "default";
  const base::TimeTicks kNow_ = base::TimeTicks::Now();
  const base::TimeTicks kExpires1_ = kNow_ + base::TimeDelta::FromDays(7);
  const base::TimeTicks kExpires2_ = kExpires1_ + base::TimeDelta::FromDays(7);

  ReportingCache cache_;
};

TEST_F(ReportingCacheTest, Reports) {
  std::vector<const ReportingReport*> reports;
  cache_.GetReports(&reports);
  EXPECT_TRUE(reports.empty());

  cache_.AddReport(kUrl1_, kGroup1_, kType_,
                   base::MakeUnique<base::DictionaryValue>(), kNow_, 0);

  cache_.GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  const ReportingReport* report = reports[0];
  ASSERT_TRUE(report);
  EXPECT_EQ(kUrl1_, report->url);
  EXPECT_EQ(kGroup1_, report->group);
  EXPECT_EQ(kType_, report->type);
  // TODO(juliatuttle): Check body?
  EXPECT_EQ(kNow_, report->queued);
  EXPECT_EQ(0, report->attempts);
  EXPECT_FALSE(cache_.IsReportPendingForTesting(report));
  EXPECT_FALSE(cache_.IsReportDoomedForTesting(report));

  cache_.IncrementReportsAttempts(reports);

  cache_.GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  report = reports[0];
  ASSERT_TRUE(report);
  EXPECT_EQ(1, report->attempts);

  cache_.RemoveReports(reports);

  cache_.GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

TEST_F(ReportingCacheTest, RemoveAllReports) {
  cache_.AddReport(kUrl1_, kGroup1_, kType_,
                   base::MakeUnique<base::DictionaryValue>(), kNow_, 0);
  cache_.AddReport(kUrl1_, kGroup1_, kType_,
                   base::MakeUnique<base::DictionaryValue>(), kNow_, 0);

  std::vector<const ReportingReport*> reports;
  cache_.GetReports(&reports);
  EXPECT_EQ(2u, reports.size());

  cache_.RemoveAllReports();

  cache_.GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

TEST_F(ReportingCacheTest, RemovePendingReports) {
  cache_.AddReport(kUrl1_, kGroup1_, kType_,
                   base::MakeUnique<base::DictionaryValue>(), kNow_, 0);

  std::vector<const ReportingReport*> reports;
  cache_.GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_FALSE(cache_.IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache_.IsReportDoomedForTesting(reports[0]));

  cache_.SetReportsPending(reports);
  EXPECT_TRUE(cache_.IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache_.IsReportDoomedForTesting(reports[0]));

  cache_.RemoveReports(reports);
  EXPECT_TRUE(cache_.IsReportPendingForTesting(reports[0]));
  EXPECT_TRUE(cache_.IsReportDoomedForTesting(reports[0]));

  // After removing report, future calls to GetReports should not return it.
  std::vector<const ReportingReport*> visible_reports;
  cache_.GetReports(&visible_reports);
  EXPECT_TRUE(visible_reports.empty());
  EXPECT_EQ(1u, cache_.GetFullReportCountForTesting());

  // After clearing pending flag, report should be deleted.
  cache_.ClearReportsPending(reports);
  EXPECT_EQ(0u, cache_.GetFullReportCountForTesting());
}

TEST_F(ReportingCacheTest, RemoveAllPendingReports) {
  cache_.AddReport(kUrl1_, kGroup1_, kType_,
                   base::MakeUnique<base::DictionaryValue>(), kNow_, 0);

  std::vector<const ReportingReport*> reports;
  cache_.GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_FALSE(cache_.IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache_.IsReportDoomedForTesting(reports[0]));

  cache_.SetReportsPending(reports);
  EXPECT_TRUE(cache_.IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache_.IsReportDoomedForTesting(reports[0]));

  cache_.RemoveAllReports();
  EXPECT_TRUE(cache_.IsReportPendingForTesting(reports[0]));
  EXPECT_TRUE(cache_.IsReportDoomedForTesting(reports[0]));

  // After removing report, future calls to GetReports should not return it.
  std::vector<const ReportingReport*> visible_reports;
  cache_.GetReports(&visible_reports);
  EXPECT_TRUE(visible_reports.empty());
  EXPECT_EQ(1u, cache_.GetFullReportCountForTesting());

  // After clearing pending flag, report should be deleted.
  cache_.ClearReportsPending(reports);
  EXPECT_EQ(0u, cache_.GetFullReportCountForTesting());
}

TEST_F(ReportingCacheTest, Endpoints) {
  cache_.SetClient(kOrigin1_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);

  const ReportingClient* client =
      FindClientInCache(&cache_, kOrigin1_, kEndpoint1_);
  ASSERT_TRUE(client);
  EXPECT_EQ(kOrigin1_, client->origin);
  EXPECT_EQ(kEndpoint1_, client->endpoint);
  EXPECT_EQ(ReportingClient::Subdomains::EXCLUDE, client->subdomains);
  EXPECT_EQ(kGroup1_, client->group);
  EXPECT_EQ(kExpires1_, client->expires);

  // Replaces original configuration with new Subdomains, group, and expires
  // values.
  cache_.SetClient(kOrigin1_, kEndpoint1_, ReportingClient::Subdomains::INCLUDE,
                   kGroup2_, kExpires2_);

  client = FindClientInCache(&cache_, kOrigin1_, kEndpoint1_);
  ASSERT_TRUE(client);
  EXPECT_EQ(kOrigin1_, client->origin);
  EXPECT_EQ(kEndpoint1_, client->endpoint);
  EXPECT_EQ(ReportingClient::Subdomains::INCLUDE, client->subdomains);
  EXPECT_EQ(kGroup2_, client->group);
  EXPECT_EQ(kExpires2_, client->expires);

  cache_.RemoveClients(std::vector<const ReportingClient*>{client});

  client = FindClientInCache(&cache_, kOrigin1_, kEndpoint1_);
  EXPECT_FALSE(client);
}

TEST_F(ReportingCacheTest, GetClientsForOriginAndGroup) {
  cache_.SetClient(kOrigin1_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);
  cache_.SetClient(kOrigin1_, kEndpoint2_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup2_, kExpires1_);
  cache_.SetClient(kOrigin2_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);

  std::vector<const ReportingClient*> clients;
  cache_.GetClientsForOriginAndGroup(kOrigin1_, kGroup1_, &clients);
  ASSERT_EQ(1u, clients.size());
  const ReportingClient* client = clients[0];
  ASSERT_TRUE(client);
  EXPECT_EQ(kOrigin1_, client->origin);
  EXPECT_EQ(kGroup1_, client->group);
}

TEST_F(ReportingCacheTest, RemoveClientForOriginAndEndpoint) {
  cache_.SetClient(kOrigin1_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);
  cache_.SetClient(kOrigin1_, kEndpoint2_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup2_, kExpires1_);
  cache_.SetClient(kOrigin2_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);

  cache_.RemoveClientForOriginAndEndpoint(kOrigin1_, kEndpoint1_);

  std::vector<const ReportingClient*> clients;
  cache_.GetClientsForOriginAndGroup(kOrigin1_, kGroup1_, &clients);
  EXPECT_TRUE(clients.empty());

  cache_.GetClientsForOriginAndGroup(kOrigin1_, kGroup2_, &clients);
  EXPECT_EQ(1u, clients.size());

  cache_.GetClientsForOriginAndGroup(kOrigin2_, kGroup1_, &clients);
  EXPECT_EQ(1u, clients.size());
}

TEST_F(ReportingCacheTest, RemoveClientsForEndpoint) {
  cache_.SetClient(kOrigin1_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);
  cache_.SetClient(kOrigin1_, kEndpoint2_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup2_, kExpires1_);
  cache_.SetClient(kOrigin2_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);

  cache_.RemoveClientsForEndpoint(kEndpoint1_);

  std::vector<const ReportingClient*> clients;
  cache_.GetClientsForOriginAndGroup(kOrigin1_, kGroup1_, &clients);
  EXPECT_TRUE(clients.empty());

  cache_.GetClientsForOriginAndGroup(kOrigin1_, kGroup2_, &clients);
  EXPECT_EQ(1u, clients.size());

  cache_.GetClientsForOriginAndGroup(kOrigin2_, kGroup1_, &clients);
  EXPECT_TRUE(clients.empty());
}

TEST_F(ReportingCacheTest, RemoveAllClients) {
  cache_.SetClient(kOrigin1_, kEndpoint1_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);
  cache_.SetClient(kOrigin2_, kEndpoint2_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup1_, kExpires1_);

  cache_.RemoveAllClients();

  std::vector<const ReportingClient*> clients;
  cache_.GetClients(&clients);
  EXPECT_TRUE(clients.empty());
}

}  // namespace
}  // namespace net
