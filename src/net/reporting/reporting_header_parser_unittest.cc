// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_header_parser.h"

#include <string>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

class ReportingHeaderParserTest : public ReportingTestBase {
 protected:
  const GURL kUrl_ = GURL("https://origin/path");
  const url::Origin kOrigin_ = url::Origin(GURL("https://origin/"));
  const GURL kEndpoint_ = GURL("https://endpoint/");
  const std::string kGroup_ = "group";
  const std::string kType_ = "type";
};

TEST_F(ReportingHeaderParserTest, Invalid) {
  static const struct {
    const char* header_value;
    const char* description;
  } kInvalidHeaderTestCases[] = {
      {"{\"max-age\":1}", "missing url"},
      {"{\"url\":0,\"max-age\":1}", "non-string url"},
      {"{\"url\":\"http://insecure/\",\"max-age\":1}", "insecure url"},

      {"{\"url\":\"https://endpoint/\"}", "missing max-age"},
      {"{\"url\":\"https://endpoint/\",\"max-age\":\"\"}",
       "non-integer max-age"},
      {"{\"url\":\"https://endpoint/\",\"max-age\":-1}", "negative max-age"},

      {"{\"url\":\"https://endpoint/\",\"max-age\":1,\"group\":0}",
       "non-string group"},

      // Note that a non-boolean includeSubdomains field is *not* invalid, per
      // the spec.

      {"[{\"url\":\"https://a/\",\"max-age\":1},"
       "{\"url\":\"https://b/\",\"max-age\":1}]",
       "wrapped in list"}};

  for (size_t i = 0; i < arraysize(kInvalidHeaderTestCases); ++i) {
    auto& test_case = kInvalidHeaderTestCases[i];
    ReportingHeaderParser::ParseHeader(context(), kUrl_,
                                       test_case.header_value);

    std::vector<const ReportingClient*> clients;
    cache()->GetClients(&clients);
    EXPECT_TRUE(clients.empty())
        << "Invalid Report-To header (" << test_case.description << ": \""
        << test_case.header_value << "\") parsed as valid.";
  }
}

TEST_F(ReportingHeaderParserTest, Valid) {
  ReportingHeaderParser::ParseHeader(
      context(), kUrl_,
      "{\"url\":\"" + kEndpoint_.spec() + "\",\"max-age\":86400}");

  const ReportingClient* client =
      FindClientInCache(cache(), kOrigin_, kEndpoint_);
  ASSERT_TRUE(client);
  EXPECT_EQ(kOrigin_, client->origin);
  EXPECT_EQ(kEndpoint_, client->endpoint);
  EXPECT_EQ(ReportingClient::Subdomains::EXCLUDE, client->subdomains);
  EXPECT_EQ(86400, (client->expires - tick_clock()->NowTicks()).InSeconds());
}

TEST_F(ReportingHeaderParserTest, Subdomains) {
  ReportingHeaderParser::ParseHeader(context(), kUrl_,
                                     "{\"url\":\"" + kEndpoint_.spec() +
                                         "\",\"max-age\":86400,"
                                         "\"includeSubdomains\":true}");

  const ReportingClient* client =
      FindClientInCache(cache(), kOrigin_, kEndpoint_);
  ASSERT_TRUE(client);
  EXPECT_EQ(ReportingClient::Subdomains::INCLUDE, client->subdomains);
}

TEST_F(ReportingHeaderParserTest, ZeroMaxAge) {
  cache()->SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                     kGroup_,
                     tick_clock()->NowTicks() + base::TimeDelta::FromDays(1));

  ReportingHeaderParser::ParseHeader(
      context(), kUrl_,
      "{\"url\":\"" + kEndpoint_.spec() + "\",\"max-age\":0}");

  EXPECT_EQ(nullptr, FindClientInCache(cache(), kOrigin_, kEndpoint_));
}

}  // namespace
}  // namespace net
