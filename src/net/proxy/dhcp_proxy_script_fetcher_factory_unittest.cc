// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/dhcp_proxy_script_fetcher.h"
#include "net/proxy/dhcp_proxy_script_fetcher_factory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

#if defined(OS_WIN)
TEST(DhcpProxyScriptFetcherFactoryTest, WindowsFetcherOnWindows) {
  DhcpProxyScriptFetcherFactory factory;
  TestURLRequestContext context;
  std::unique_ptr<DhcpProxyScriptFetcher> fetcher(factory.Create(&context));
  ASSERT_TRUE(fetcher.get());
  EXPECT_EQ("win", fetcher->GetFetcherName());
}

#else  // !defined(OS_WIN)

TEST(DhcpProxyScriptFetcherFactoryTest, ReturnNullOnUnsupportedPlatforms) {
  DhcpProxyScriptFetcherFactory factory;
  TestURLRequestContext context;
  std::unique_ptr<DhcpProxyScriptFetcher> fetcher(factory.Create(&context));
  ASSERT_TRUE(fetcher.get());
  EXPECT_EQ("do nothing", fetcher->GetFetcherName());
}

#endif  // defined(OS_WIN)

}  // namespace
}  // namespace net
