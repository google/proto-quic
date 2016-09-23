// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/dhcp_proxy_script_fetcher.h"
#include "net/proxy/dhcp_proxy_script_fetcher_factory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

TEST(DhcpProxyScriptFetcherFactoryTest, DoNothingWhenDisabled) {
  DhcpProxyScriptFetcherFactory factory;
  factory.set_enabled(false);
  std::unique_ptr<DhcpProxyScriptFetcher> fetcher(factory.Create(NULL));
  EXPECT_EQ("", fetcher->GetFetcherName());
}

#if defined(OS_WIN)
TEST(DhcpProxyScriptFetcherFactoryTest, WindowsFetcherOnWindows) {
  DhcpProxyScriptFetcherFactory factory;
  factory.set_enabled(true);

  std::unique_ptr<TestURLRequestContext> context(new TestURLRequestContext());
  std::unique_ptr<DhcpProxyScriptFetcher> fetcher(
      factory.Create(context.get()));
  EXPECT_EQ("win", fetcher->GetFetcherName());
}
#endif  // defined(OS_WIN)

TEST(DhcpProxyScriptFetcherFactoryTest, IsSupported) {
#if defined(OS_WIN)
  ASSERT_TRUE(DhcpProxyScriptFetcherFactory::IsSupported());
#else
  ASSERT_FALSE(DhcpProxyScriptFetcherFactory::IsSupported());
#endif  // defined(OS_WIN)
}

TEST(DhcpProxyScriptFetcherFactoryTest, SetEnabled) {
  DhcpProxyScriptFetcherFactory factory;
#if defined(OS_WIN)
  EXPECT_TRUE(factory.enabled());
#else
  EXPECT_FALSE(factory.enabled());
#endif  // defined(OS_WIN)

  factory.set_enabled(false);
  EXPECT_FALSE(factory.enabled());

  factory.set_enabled(true);
#if defined(OS_WIN)
  EXPECT_TRUE(factory.enabled());
#else
  EXPECT_FALSE(factory.enabled());
#endif  // defined(OS_WIN)
}

}  // namespace
}  // namespace net
