// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_service.h"

#include <cstdarg>
#include <string>
#include <vector>

#include "base/format_macros.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_delegate.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/dhcp_proxy_script_fetcher.h"
#include "net/proxy/mock_proxy_resolver.h"
#include "net/proxy/mock_proxy_script_fetcher.h"
#include "net/proxy/proxy_config_service.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_script_fetcher.h"
#include "net/proxy/proxy_server.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using net::test::IsError;
using net::test::IsOk;

using base::ASCIIToUTF16;

// TODO(eroman): Write a test which exercises
//              ProxyService::SuspendAllPendingRequests().
namespace net {
namespace {

// This polling policy will decide to poll every 1 ms.
class ImmediatePollPolicy : public ProxyService::PacPollPolicy {
 public:
  ImmediatePollPolicy() {}

  Mode GetNextDelay(int error,
                    base::TimeDelta current_delay,
                    base::TimeDelta* next_delay) const override {
    *next_delay = base::TimeDelta::FromMilliseconds(1);
    return MODE_USE_TIMER;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ImmediatePollPolicy);
};

// This polling policy chooses a fantastically large delay. In other words, it
// will never trigger a poll
class NeverPollPolicy : public ProxyService::PacPollPolicy {
 public:
  NeverPollPolicy() {}

  Mode GetNextDelay(int error,
                    base::TimeDelta current_delay,
                    base::TimeDelta* next_delay) const override {
    *next_delay = base::TimeDelta::FromDays(60);
    return MODE_USE_TIMER;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(NeverPollPolicy);
};

// This polling policy starts a poll immediately after network activity.
class ImmediateAfterActivityPollPolicy : public ProxyService::PacPollPolicy {
 public:
  ImmediateAfterActivityPollPolicy() {}

  Mode GetNextDelay(int error,
                    base::TimeDelta current_delay,
                    base::TimeDelta* next_delay) const override {
    *next_delay = base::TimeDelta();
    return MODE_START_AFTER_ACTIVITY;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ImmediateAfterActivityPollPolicy);
};

// This test fixture is used to partially disable the background polling done by
// the ProxyService (which it uses to detect whenever its PAC script contents or
// WPAD results have changed).
//
// We disable the feature by setting the poll interval to something really
// large, so it will never actually be reached even on the slowest bots that run
// these tests.
//
// We disable the polling in order to avoid any timing dependencies in the
// tests. If the bot were to run the tests very slowly and we hadn't disabled
// polling, then it might start a background re-try in the middle of our test
// and confuse our expectations leading to flaky failures.
//
// The tests which verify the polling code re-enable the polling behavior but
// are careful to avoid timing problems.
class ProxyServiceTest : public testing::Test {
 protected:
  void SetUp() override {
    testing::Test::SetUp();
    previous_policy_ =
        ProxyService::set_pac_script_poll_policy(&never_poll_policy_);
  }

  void TearDown() override {
    // Restore the original policy.
    ProxyService::set_pac_script_poll_policy(previous_policy_);
    testing::Test::TearDown();
  }

 private:
  NeverPollPolicy never_poll_policy_;
  const ProxyService::PacPollPolicy* previous_policy_;
};

const char kValidPacScript1[] = "pac-script-v1-FindProxyForURL";
const char kValidPacScript2[] = "pac-script-v2-FindProxyForURL";

class MockProxyConfigService: public ProxyConfigService {
 public:
  explicit MockProxyConfigService(const ProxyConfig& config)
      : availability_(CONFIG_VALID),
        config_(config) {
  }

  explicit MockProxyConfigService(const std::string& pac_url)
      : availability_(CONFIG_VALID),
        config_(ProxyConfig::CreateFromCustomPacURL(GURL(pac_url))) {
  }

  void AddObserver(Observer* observer) override {
    observers_.AddObserver(observer);
  }

  void RemoveObserver(Observer* observer) override {
    observers_.RemoveObserver(observer);
  }

  ConfigAvailability GetLatestProxyConfig(ProxyConfig* results) override {
    if (availability_ == CONFIG_VALID)
      *results = config_;
    return availability_;
  }

  void SetConfig(const ProxyConfig& config) {
    availability_ = CONFIG_VALID;
    config_ = config;
    for (auto& observer : observers_)
      observer.OnProxyConfigChanged(config_, availability_);
  }

 private:
  ConfigAvailability availability_;
  ProxyConfig config_;
  base::ObserverList<Observer, true> observers_;
};

// A test network delegate that exercises the OnResolveProxy callback.
class TestResolveProxyDelegate : public ProxyDelegate {
 public:
  TestResolveProxyDelegate()
      : on_resolve_proxy_called_(false),
        add_proxy_(false),
        remove_proxy_(false),
        proxy_service_(nullptr) {}

  void OnResolveProxy(const GURL& url,
                      const std::string& method,
                      const ProxyService& proxy_service,
                      ProxyInfo* result) override {
    method_ = method;
    on_resolve_proxy_called_ = true;
    proxy_service_ = &proxy_service;
    DCHECK(!add_proxy_ || !remove_proxy_);
    if (add_proxy_) {
      result->UseNamedProxy("delegate_proxy.com");
    } else if (remove_proxy_) {
      result->UseDirect();
    }
  }

  bool on_resolve_proxy_called() const {
    return on_resolve_proxy_called_;
  }

  const std::string& method() const { return method_; }

  void set_add_proxy(bool add_proxy) {
    add_proxy_ = add_proxy;
  }

  void set_remove_proxy(bool remove_proxy) {
    remove_proxy_ = remove_proxy;
  }

  const ProxyService* proxy_service() const {
    return proxy_service_;
  }

  void OnTunnelConnectCompleted(const HostPortPair& endpoint,
                                const HostPortPair& proxy_server,
                                int net_error) override {}
  void OnFallback(const ProxyServer& bad_proxy, int net_error) override {}
  void OnBeforeTunnelRequest(const HostPortPair& proxy_server,
                             HttpRequestHeaders* extra_headers) override {}
  void OnTunnelHeadersReceived(
      const HostPortPair& origin,
      const HostPortPair& proxy_server,
      const HttpResponseHeaders& response_headers) override {}
  bool IsTrustedSpdyProxy(const net::ProxyServer& proxy_server) override {
    return true;
  }
  void GetAlternativeProxy(
      const GURL& url,
      const ProxyServer& resolved_proxy_server,
      ProxyServer* alternative_proxy_server) const override {}
  void OnAlternativeProxyBroken(
      const ProxyServer& alternative_proxy_server) override {}
  ProxyServer GetDefaultAlternativeProxy() const override {
    return ProxyServer();
  }

 private:
  bool on_resolve_proxy_called_;
  bool add_proxy_;
  bool remove_proxy_;
  std::string method_;
  const ProxyService* proxy_service_;
};

// A test network delegate that exercises the OnProxyFallback callback.
class TestProxyFallbackProxyDelegate : public ProxyDelegate {
 public:
  TestProxyFallbackProxyDelegate()
      : on_proxy_fallback_called_(false), proxy_fallback_net_error_(OK) {}

  // ProxyDelegate implementation:
  void OnResolveProxy(const GURL& url,
                      const std::string& method,
                      const ProxyService& proxy_service,
                      ProxyInfo* result) override {}
  void OnTunnelConnectCompleted(const HostPortPair& endpoint,
                                const HostPortPair& proxy_server,
                                int net_error) override {}
  void OnFallback(const ProxyServer& bad_proxy, int net_error) override {
    proxy_server_ = bad_proxy;
    proxy_fallback_net_error_ = net_error;
    on_proxy_fallback_called_ = true;
  }
  void OnBeforeTunnelRequest(const HostPortPair& proxy_server,
                             HttpRequestHeaders* extra_headers) override {}
  void OnTunnelHeadersReceived(
      const HostPortPair& origin,
      const HostPortPair& proxy_server,
      const HttpResponseHeaders& response_headers) override {}
  bool IsTrustedSpdyProxy(const net::ProxyServer& proxy_server) override {
    return true;
  }
  void GetAlternativeProxy(
      const GURL& url,
      const ProxyServer& resolved_proxy_server,
      ProxyServer* alternative_proxy_server) const override {}
  void OnAlternativeProxyBroken(
      const ProxyServer& alternative_proxy_server) override {}
  ProxyServer GetDefaultAlternativeProxy() const override {
    return ProxyServer();
  }

  bool on_proxy_fallback_called() const {
    return on_proxy_fallback_called_;
  }

  const ProxyServer& proxy_server() const {
    return proxy_server_;
  }

  int proxy_fallback_net_error() const {
    return proxy_fallback_net_error_;
  }

 private:
  bool on_proxy_fallback_called_;
  ProxyServer proxy_server_;
  int proxy_fallback_net_error_;
};

using JobMap = std::map<GURL, MockAsyncProxyResolver::Job*>;

// Given a jobmap and a list of target URLs |urls|, asserts that the set of URLs
// of the jobs appearing in |list| is exactly the set of URLs in |urls|.
JobMap GetJobsForURLs(const JobMap& map, const std::vector<GURL>& urls) {
  size_t a = urls.size();
  size_t b = map.size();
  if (a != b) {
    ADD_FAILURE() << "map size (" << map.size() << ") != urls size ("
                  << urls.size() << ")";
    return map;
  }
  for (const auto& it : urls) {
    if (map.count(it) != 1U) {
      ADD_FAILURE() << "url not in map: " << it.spec();
      break;
    }
  }
  return map;
}

// Given a MockAsyncProxyResolver |resolver| and some GURLs, validates that the
// set of pending request URLs for |resolver| is exactly the supplied list of
// URLs and returns a map from URLs to the corresponding pending jobs.
JobMap GetPendingJobsForURLs(const MockAsyncProxyResolver& resolver,
                             const GURL& url1 = GURL(),
                             const GURL& url2 = GURL(),
                             const GURL& url3 = GURL()) {
  std::vector<GURL> urls;
  if (!url1.is_empty())
    urls.push_back(url1);
  if (!url2.is_empty())
    urls.push_back(url2);
  if (!url3.is_empty())
    urls.push_back(url3);

  JobMap map;
  for (MockAsyncProxyResolver::Job* it : resolver.pending_jobs()) {
    DCHECK(it);
    map[it->url()] = it;
  }

  return GetJobsForURLs(map, urls);
}

// Given a MockAsyncProxyResolver |resolver| and some GURLs, validates that the
// set of cancelled request URLs for |resolver| is exactly the supplied list of
// URLs and returns a map from URLs to the corresponding cancelled jobs.
JobMap GetCancelledJobsForURLs(const MockAsyncProxyResolver& resolver,
                               const GURL& url1 = GURL(),
                               const GURL& url2 = GURL(),
                               const GURL& url3 = GURL()) {
  std::vector<GURL> urls;
  if (!url1.is_empty())
    urls.push_back(url1);
  if (!url2.is_empty())
    urls.push_back(url2);
  if (!url3.is_empty())
    urls.push_back(url3);

  JobMap map;
  for (const std::unique_ptr<MockAsyncProxyResolver::Job>& it :
       resolver.cancelled_jobs()) {
    DCHECK(it);
    map[it->url()] = it.get();
  }

  return GetJobsForURLs(map, urls);
}

}  // namespace

TEST_F(ProxyServiceTest, Direct) {
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);
  ProxyService service(
      base::MakeUnique<MockProxyConfigService>(ProxyConfig::CreateDirect()),
      base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  BoundTestNetLog log;
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, log.bound());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(factory->pending_requests().empty());

  EXPECT_TRUE(info.is_direct());
  EXPECT_TRUE(info.proxy_resolve_start_time().is_null());
  EXPECT_TRUE(info.proxy_resolve_end_time().is_null());

  // Check the NetLog was filled correctly.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(3u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SERVICE));
  EXPECT_TRUE(LogContainsEvent(
      entries, 1, NetLogEventType::PROXY_SERVICE_RESOLVED_PROXY_LIST,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(entries, 2, NetLogEventType::PROXY_SERVICE));
}

TEST_F(ProxyServiceTest, OnResolveProxyCallbackAddProxy) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080");
  config.set_auto_detect(false);
  config.proxy_rules().bypass_rules.ParseFromString("*.org");

  ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                       nullptr, nullptr);

  GURL url("http://www.google.com/");
  GURL bypass_url("http://internet.org");

  ProxyInfo info;
  TestCompletionCallback callback;
  BoundTestNetLog log;

  // First, warm up the ProxyService.
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, log.bound());
  EXPECT_THAT(rv, IsOk());

  // Verify that network delegate is invoked.
  TestResolveProxyDelegate delegate;
  rv = service.ResolveProxy(url, "GET", &info, callback.callback(), nullptr,
                            &delegate, log.bound());
  EXPECT_TRUE(delegate.on_resolve_proxy_called());
  EXPECT_EQ(&service, delegate.proxy_service());
  EXPECT_EQ(delegate.method(), "GET");

  // Verify that the ProxyDelegate's behavior is stateless across
  // invocations of ResolveProxy. Start by having the callback add a proxy
  // and checking that subsequent jobs are not affected.
  delegate.set_add_proxy(true);

  // Callback should interpose:
  rv = service.ResolveProxy(url, "GET", &info, callback.callback(), nullptr,
                            &delegate, log.bound());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ(info.proxy_server().host_port_pair().host(), "delegate_proxy.com");
  delegate.set_add_proxy(false);

  // Check non-bypassed URL:
  rv = service.ResolveProxy(url, "GET", &info, callback.callback(), nullptr,
                            &delegate, log.bound());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ(info.proxy_server().host_port_pair().host(), "foopy1");

  // Check bypassed URL:
  rv = service.ResolveProxy(bypass_url, "GET", &info, callback.callback(),
                            nullptr, &delegate, log.bound());
  EXPECT_TRUE(info.is_direct());
}

TEST_F(ProxyServiceTest, OnResolveProxyCallbackRemoveProxy) {
  // Same as OnResolveProxyCallbackAddProxy, but verify that the
  // ProxyDelegate's behavior is stateless across invocations after it
  // *removes* a proxy.
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080");
  config.set_auto_detect(false);
  config.proxy_rules().bypass_rules.ParseFromString("*.org");

  ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                       nullptr, nullptr);

  GURL url("http://www.google.com/");
  GURL bypass_url("http://internet.org");

  ProxyInfo info;
  TestCompletionCallback callback;
  BoundTestNetLog log;

  // First, warm up the ProxyService.
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, log.bound());
  EXPECT_THAT(rv, IsOk());

  TestResolveProxyDelegate delegate;
  delegate.set_remove_proxy(true);

  // Callback should interpose:
  rv = service.ResolveProxy(url, "GET", &info, callback.callback(), nullptr,
                            &delegate, log.bound());
  EXPECT_TRUE(info.is_direct());
  delegate.set_remove_proxy(false);

  // Check non-bypassed URL:
  rv = service.ResolveProxy(url, "GET", &info, callback.callback(), nullptr,
                            &delegate, log.bound());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ(info.proxy_server().host_port_pair().host(), "foopy1");

  // Check bypassed URL:
  rv = service.ResolveProxy(bypass_url, "GET", &info, callback.callback(),
                            nullptr, &delegate, log.bound());
  EXPECT_TRUE(info.is_direct());
}

TEST_F(ProxyServiceTest, PAC) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  ProxyService::PacRequest* request;
  BoundTestNetLog log;

  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                &request, nullptr, log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, service.GetLoadState(request));

  ASSERT_EQ(1u, factory->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy:80", info.proxy_server().ToURI());
  EXPECT_TRUE(info.did_use_pac_script());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // Check the NetLog was filled correctly.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(5u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SERVICE));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PROXY_SERVICE_WAITING_FOR_INIT_PAC));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PROXY_SERVICE_WAITING_FOR_INIT_PAC));
  EXPECT_TRUE(LogContainsEndEvent(entries, 4, NetLogEventType::PROXY_SERVICE));
}

// Test that the proxy resolver does not see the URL's username/password
// or its reference section.
TEST_F(ProxyServiceTest, PAC_NoIdentityOrHash) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://username:password@www.google.com/?ref#hash#hash");

  ProxyInfo info;
  TestCompletionCallback callback;
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  // The URL should have been simplified, stripping the username/password/hash.
  EXPECT_EQ(GURL("http://www.google.com/?ref"),
            resolver.pending_jobs()[0]->url());

  // We end here without ever completing the request -- destruction of
  // ProxyService will cancel the outstanding request.
}

TEST_F(ProxyServiceTest, PAC_FailoverWithoutDirect) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy:8080", info.proxy_server().ToURI());
  EXPECT_TRUE(info.did_use_pac_script());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // Now, imagine that connecting to foopy:8080 fails: there is nothing
  // left to fallback to, since our proxy list was NOT terminated by
  // DIRECT.
  TestResolveProxyDelegate proxy_delegate;
  TestCompletionCallback callback2;
  ProxyServer expected_proxy_server = info.proxy_server();
  rv = service.ReconsiderProxyAfterError(
      url, "GET", ERR_PROXY_CONNECTION_FAILED, &info, callback2.callback(),
      nullptr, &proxy_delegate, NetLogWithSource());
  // ReconsiderProxyAfterError returns error indicating nothing left.
  EXPECT_THAT(rv, IsError(ERR_FAILED));
  EXPECT_TRUE(info.is_empty());
}

// Test that if the execution of the PAC script fails (i.e. javascript runtime
// error), and the PAC settings are non-mandatory, that we fall-back to direct.
TEST_F(ProxyServiceTest, PAC_RuntimeError) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://this-causes-js-error/");

  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Simulate a failure in the PAC executor.
  resolver.pending_jobs()[0]->CompleteNow(ERR_PAC_SCRIPT_FAILED);

  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  // Since the PAC script was non-mandatory, we should have fallen-back to
  // DIRECT.
  EXPECT_TRUE(info.is_direct());
  EXPECT_TRUE(info.did_use_pac_script());
  EXPECT_EQ(1, info.config_id());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
}

// The proxy list could potentially contain the DIRECT fallback choice
// in a location other than the very end of the list, and could even
// specify it multiple times.
//
// This is not a typical usage, but we will obey it.
// (If we wanted to disallow this type of input, the right place to
// enforce it would be in parsing the PAC result string).
//
// This test will use the PAC result string:
//
//   "DIRECT ; PROXY foobar:10 ; DIRECT ; PROXY foobar:20"
//
// For which we expect it to try DIRECT, then foobar:10, then DIRECT again,
// then foobar:20, and then give up and error.
//
// The important check of this test is to make sure that DIRECT is not somehow
// cached as being a bad proxy.
TEST_F(ProxyServiceTest, PAC_FailoverAfterDirect) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UsePacString(
      "DIRECT ; PROXY foobar:10 ; DIRECT ; PROXY foobar:20");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Fallback 1.
  TestCompletionCallback callback2;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback2.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foobar:10", info.proxy_server().ToURI());

  // Fallback 2.
  TestResolveProxyDelegate proxy_delegate;
  ProxyServer expected_proxy_server3 = info.proxy_server();
  TestCompletionCallback callback3;
  rv = service.ReconsiderProxyAfterError(
      url, "GET", ERR_PROXY_CONNECTION_FAILED, &info, callback3.callback(),
      nullptr, &proxy_delegate, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info.is_direct());

  // Fallback 3.
  ProxyServer expected_proxy_server4 = info.proxy_server();
  TestCompletionCallback callback4;
  rv = service.ReconsiderProxyAfterError(
      url, "GET", ERR_PROXY_CONNECTION_FAILED, &info, callback4.callback(),
      nullptr, &proxy_delegate, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foobar:20", info.proxy_server().ToURI());

  // Fallback 4 -- Nothing to fall back to!
  ProxyServer expected_proxy_server5 = info.proxy_server();
  TestCompletionCallback callback5;
  rv = service.ReconsiderProxyAfterError(
      url, "GET", ERR_PROXY_CONNECTION_FAILED, &info, callback5.callback(),
      nullptr, &proxy_delegate, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_FAILED));
  EXPECT_TRUE(info.is_empty());
}

TEST_F(ProxyServiceTest, PAC_ConfigSourcePropagates) {
  // Test whether the ProxyConfigSource set by the ProxyConfigService is applied
  // to ProxyInfo after the proxy is resolved via a PAC script.
  ProxyConfig config =
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac"));
  config.set_source(PROXY_CONFIG_SOURCE_TEST);

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Resolve something.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback;
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(PROXY_CONFIG_SOURCE_TEST, info.config_source());
  EXPECT_TRUE(info.did_use_pac_script());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
}

TEST_F(ProxyServiceTest, ProxyResolverFails) {
  // Test what happens when the ProxyResolver fails. The download and setting
  // of the PAC script have already succeeded, so this corresponds with a
  // javascript runtime error while calling FindProxyForURL().

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Fail the first resolve request in MockAsyncProxyResolver.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // Although the proxy resolver failed the request, ProxyService implicitly
  // falls-back to DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Failed PAC executions still have proxy resolution times.
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // The second resolve request will try to run through the proxy resolver,
  // regardless of whether the first request failed in it.
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url, std::string(), &info, callback2.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time we will have the resolver succeed (perhaps the PAC script has
  // a dependency on the current time).
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy_valid:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy_valid:8080", info.proxy_server().ToURI());
}

TEST_F(ProxyServiceTest, ProxyResolverTerminatedDuringRequest) {
  // Test what happens when the ProxyResolver fails with a fatal error while
  // a GetProxyForURL() call is in progress.

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Fail the first resolve request in MockAsyncProxyResolver.
  resolver.pending_jobs()[0]->CompleteNow(ERR_PAC_SCRIPT_TERMINATED);

  // Although the proxy resolver failed the request, ProxyService implicitly
  // falls-back to DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Failed PAC executions still have proxy resolution times.
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // With no other requests, the ProxyService waits for a new request before
  // initializing a new ProxyResolver.
  EXPECT_TRUE(factory->pending_requests().empty());

  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url, std::string(), &info, callback2.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time we will have the resolver succeed.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy_valid:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy_valid:8080", info.proxy_server().ToURI());
}

TEST_F(ProxyServiceTest,
       ProxyResolverTerminatedDuringRequestWithConcurrentRequest) {
  // Test what happens when the ProxyResolver fails with a fatal error while
  // a GetProxyForURL() call is in progress.

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start two resolve requests.
  GURL url1("http://www.google.com/");
  GURL url2("https://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv =
      service.ResolveProxy(url1, std::string(), &info, callback1.callback(),
                           nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url2, std::string(), &info, callback2.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, factory->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2);

  // Fail the first resolve request in MockAsyncProxyResolver.
  jobs[url1]->CompleteNow(ERR_PAC_SCRIPT_TERMINATED);

  // Although the proxy resolver failed the request, ProxyService implicitly
  // falls-back to DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info.is_direct());

  // Failed PAC executions still have proxy resolution times.
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // The second request is cancelled when the proxy resolver terminates.
  jobs = GetCancelledJobsForURLs(resolver, url2);

  // Since a second request was in progress, the ProxyService starts
  // initializating a new ProxyResolver.
  ASSERT_EQ(1u, factory->pending_requests().size());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  jobs = GetPendingJobsForURLs(resolver, url2);

  // This request succeeds.
  jobs[url2]->results()->UseNamedProxy("foopy_valid:8080");
  jobs[url2]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy_valid:8080", info.proxy_server().ToURI());
}

TEST_F(ProxyServiceTest, ProxyScriptFetcherFailsDownloadingMandatoryPac) {
  // Test what happens when the ProxyScriptResolver fails to download a
  // mandatory PAC script.

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));
  config.set_pac_mandatory(true);

  MockProxyConfigService* config_service = new MockProxyConfigService(config);

  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNow(ERR_FAILED, nullptr);

  ASSERT_EQ(0u, factory->pending_requests().size());
  // As the proxy resolver factory failed the request and is configured for a
  // mandatory PAC script, ProxyService must not implicitly fall-back to DIRECT.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback1.WaitForResult());
  EXPECT_FALSE(info.is_direct());

  // As the proxy resolver factory failed the request and is configured for a
  // mandatory PAC script, ProxyService must not implicitly fall-back to DIRECT.
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url, std::string(), &info, callback2.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
  EXPECT_FALSE(info.is_direct());
}

TEST_F(ProxyServiceTest, ProxyResolverFailsParsingJavaScriptMandatoryPac) {
  // Test what happens when the ProxyResolver fails that is configured to use a
  // mandatory PAC script. The download of the PAC script has already
  // succeeded but the PAC script contains no valid javascript.

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));
  config.set_pac_mandatory(true);

  MockProxyConfigService* config_service = new MockProxyConfigService(config);

  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::MakeUnique<DoNothingDhcpProxyScriptFetcher>());

  // Start resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback;
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // Downloading the PAC script succeeds.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, "invalid-script-contents");

  EXPECT_FALSE(fetcher->has_pending_request());
  ASSERT_EQ(0u, factory->pending_requests().size());

  // Since ProxyScriptDecider failed to identify a valid PAC and PAC was
  // mandatory for this configuration, the ProxyService must not implicitly
  // fall-back to DIRECT.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback.WaitForResult());
  EXPECT_FALSE(info.is_direct());
}

TEST_F(ProxyServiceTest, ProxyResolverFailsInJavaScriptMandatoryPac) {
  // Test what happens when the ProxyResolver fails that is configured to use a
  // mandatory PAC script. The download and setting of the PAC script have
  // already succeeded, so this corresponds with a javascript runtime error
  // while calling FindProxyForURL().

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));
  config.set_pac_mandatory(true);

  MockProxyConfigService* config_service = new MockProxyConfigService(config);

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start first resolve request.
  GURL url("http://www.google.com/");
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Fail the first resolve request in MockAsyncProxyResolver.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // As the proxy resolver failed the request and is configured for a mandatory
  // PAC script, ProxyService must not implicitly fall-back to DIRECT.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback1.WaitForResult());
  EXPECT_FALSE(info.is_direct());

  // The second resolve request will try to run through the proxy resolver,
  // regardless of whether the first request failed in it.
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url, std::string(), &info, callback2.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time we will have the resolver succeed (perhaps the PAC script has
  // a dependency on the current time).
  resolver.pending_jobs()[0]->results()->UseNamedProxy("foopy_valid:8080");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy_valid:8080", info.proxy_server().ToURI());
}

TEST_F(ProxyServiceTest, ProxyFallback) {
  // Test what happens when we specify multiple proxy servers and some of them
  // are bad.

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  // Get the proxy information.
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
  base::TimeTicks proxy_resolve_start_time = info.proxy_resolve_start_time();
  base::TimeTicks proxy_resolve_end_time = info.proxy_resolve_end_time();

  // Fake an error on the proxy.
  TestCompletionCallback callback2;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback2.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  // Proxy times should not have been modified by fallback.
  EXPECT_EQ(proxy_resolve_start_time, info.proxy_resolve_start_time());
  EXPECT_EQ(proxy_resolve_end_time, info.proxy_resolve_end_time());

  // The second proxy should be specified.
  EXPECT_EQ("foopy2:9090", info.proxy_server().ToURI());
  // Report back that the second proxy worked.  This will globally mark the
  // first proxy as bad.
  TestProxyFallbackProxyDelegate test_delegate;
  service.ReportSuccess(info, &test_delegate);
  EXPECT_EQ("foopy1:8080", test_delegate.proxy_server().ToURI());
  EXPECT_EQ(ERR_PROXY_CONNECTION_FAILED,
            test_delegate.proxy_fallback_net_error());

  TestCompletionCallback callback3;
  rv = service.ResolveProxy(url, std::string(), &info, callback3.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver -- the second result is already known
  // to be bad, so we will not try to use it initially.
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy3:7070;foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy3:7070", info.proxy_server().ToURI());

  // Proxy times should have been updated, so get them again.
  EXPECT_LE(proxy_resolve_end_time, info.proxy_resolve_start_time());
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
  proxy_resolve_start_time = info.proxy_resolve_start_time();
  proxy_resolve_end_time = info.proxy_resolve_end_time();

  // We fake another error. It should now try the third one.
  TestCompletionCallback callback4;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback4.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("foopy2:9090", info.proxy_server().ToURI());

  // We fake another error. At this point we have tried all of the
  // proxy servers we thought were valid; next we try the proxy server
  // that was in our bad proxies map (foopy1:8080).
  TestCompletionCallback callback5;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback5.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  // Fake another error, the last proxy is gone, the list should now be empty,
  // so there is nothing left to try.
  TestCompletionCallback callback6;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback6.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_FAILED));
  EXPECT_FALSE(info.is_direct());
  EXPECT_TRUE(info.is_empty());

  // Proxy times should not have been modified by fallback.
  EXPECT_EQ(proxy_resolve_start_time, info.proxy_resolve_start_time());
  EXPECT_EQ(proxy_resolve_end_time, info.proxy_resolve_end_time());

  // Look up proxies again
  TestCompletionCallback callback7;
  rv = service.ResolveProxy(url, std::string(), &info, callback7.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This time, the first 3 results have been found to be bad, but only the
  // first proxy has been confirmed ...
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy3:7070;foopy2:9090;foopy4:9091");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // ... therefore, we should see the second proxy first.
  EXPECT_THAT(callback7.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy3:7070", info.proxy_server().ToURI());

  EXPECT_LE(proxy_resolve_end_time, info.proxy_resolve_start_time());
  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  // TODO(nsylvain): Test that the proxy can be retried after the delay.
}

// This test is similar to ProxyFallback, but this time we have an explicit
// fallback choice to DIRECT.
TEST_F(ProxyServiceTest, ProxyFallbackToDirect) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  // Get the proxy information.
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UsePacString(
      "PROXY foopy1:8080; PROXY foopy2:9090; DIRECT");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Get the first result.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  // Fake an error on the proxy.
  TestCompletionCallback callback2;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback2.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  // Now we get back the second proxy.
  EXPECT_EQ("foopy2:9090", info.proxy_server().ToURI());

  // Fake an error on this proxy as well.
  TestCompletionCallback callback3;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback3.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  // Finally, we get back DIRECT.
  EXPECT_TRUE(info.is_direct());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());

  // Now we tell the proxy service that even DIRECT failed.
  TestCompletionCallback callback4;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback4.callback(), nullptr, nullptr, NetLogWithSource());
  // There was nothing left to try after DIRECT, so we are out of
  // choices.
  EXPECT_THAT(rv, IsError(ERR_FAILED));
}

TEST_F(ProxyServiceTest, ProxyFallback_NewSettings) {
  // Test proxy failover when new settings are available.

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  // Get the proxy information.
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // Set the result in proxy resolver.
  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  // Fake an error on the proxy, and also a new configuration on the proxy.
  config_service->SetConfig(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy-new/proxy.pac")));

  TestCompletionCallback callback2;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback2.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy-new/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first proxy is still there since the configuration changed.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  // We fake another error. It should now ignore the first one.
  TestCompletionCallback callback3;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback3.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("foopy2:9090", info.proxy_server().ToURI());

  // We simulate a new configuration.
  config_service->SetConfig(
      ProxyConfig::CreateFromCustomPacURL(
          GURL("http://foopy-new2/proxy.pac")));

  // We fake another error. It should go back to the first proxy.
  TestCompletionCallback callback4;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback4.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy-new2/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback4.WaitForResult(), IsOk());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
}

TEST_F(ProxyServiceTest, ProxyFallback_BadConfig) {
  // Test proxy failover when the configuration is bad.

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  // Get the proxy information.
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  // Fake a proxy error.
  TestCompletionCallback callback2;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback2.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  // The first proxy is ignored, and the second one is selected.
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy2:9090", info.proxy_server().ToURI());

  // Fake a PAC failure.
  ProxyInfo info2;
  TestCompletionCallback callback3;
  rv = service.ResolveProxy(url, std::string(), &info2, callback3.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This simulates a javascript runtime error in the PAC script.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // Although the resolver failed, the ProxyService will implicitly fall-back
  // to a DIRECT connection.
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_TRUE(info2.is_direct());
  EXPECT_FALSE(info2.is_empty());

  // The PAC script will work properly next time and successfully return a
  // proxy list. Since we have not marked the configuration as bad, it should
  // "just work" the next time we call it.
  ProxyInfo info3;
  TestCompletionCallback callback4;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info3,
      callback4.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first proxy is not there since the it was added to the bad proxies
  // list by the earlier ReconsiderProxyAfterError().
  EXPECT_THAT(callback4.WaitForResult(), IsOk());
  EXPECT_FALSE(info3.is_direct());
  EXPECT_EQ("foopy1:8080", info3.proxy_server().ToURI());

  EXPECT_FALSE(info.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info.proxy_resolve_end_time().is_null());
  EXPECT_LE(info.proxy_resolve_start_time(), info.proxy_resolve_end_time());
}

TEST_F(ProxyServiceTest, ProxyFallback_BadConfigMandatory) {
  // Test proxy failover when the configuration is bad.

  ProxyConfig config(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac")));

  config.set_pac_mandatory(true);
  MockProxyConfigService* config_service = new MockProxyConfigService(config);

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  // Get the proxy information.
  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(url, std::string(), &info, callback1.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first item is valid.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  // Fake a proxy error.
  TestCompletionCallback callback2;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info,
      callback2.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  // The first proxy is ignored, and the second one is selected.
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy2:9090", info.proxy_server().ToURI());

  // Fake a PAC failure.
  ProxyInfo info2;
  TestCompletionCallback callback3;
  rv = service.ResolveProxy(url, std::string(), &info2, callback3.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  // This simulates a javascript runtime error in the PAC script.
  resolver.pending_jobs()[0]->CompleteNow(ERR_FAILED);

  // Although the resolver failed, the ProxyService will NOT fall-back
  // to a DIRECT connection as it is configured as mandatory.
  EXPECT_EQ(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED,
            callback3.WaitForResult());
  EXPECT_FALSE(info2.is_direct());
  EXPECT_TRUE(info2.is_empty());

  // The PAC script will work properly next time and successfully return a
  // proxy list. Since we have not marked the configuration as bad, it should
  // "just work" the next time we call it.
  ProxyInfo info3;
  TestCompletionCallback callback4;
  rv = service.ReconsiderProxyAfterError(
      url, std::string(), ERR_PROXY_CONNECTION_FAILED, &info3,
      callback4.callback(), nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

  resolver.pending_jobs()[0]->results()->UseNamedProxy(
      "foopy1:8080;foopy2:9090");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // The first proxy is not there since the it was added to the bad proxies
  // list by the earlier ReconsiderProxyAfterError().
  EXPECT_THAT(callback4.WaitForResult(), IsOk());
  EXPECT_FALSE(info3.is_direct());
  EXPECT_EQ("foopy1:8080", info3.proxy_server().ToURI());
}

TEST_F(ProxyServiceTest, ProxyBypassList) {
  // Test that the proxy bypass rules are consulted.

  TestCompletionCallback callback[2];
  ProxyInfo info[2];
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080;foopy2:9090");
  config.set_auto_detect(false);
  config.proxy_rules().bypass_rules.ParseFromString("*.org");

  ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                       nullptr, nullptr);

  int rv;
  GURL url1("http://www.webkit.org");
  GURL url2("http://www.webkit.com");

  // Request for a .org domain should bypass proxy.
  rv = service.ResolveProxy(url1, std::string(), &info[0],
                            callback[0].callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info[0].is_direct());

  // Request for a .com domain hits the proxy.
  rv = service.ResolveProxy(url2, std::string(), &info[1],
                            callback[1].callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("foopy1:8080", info[1].proxy_server().ToURI());
}

TEST_F(ProxyServiceTest, MarkProxiesAsBadTests) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString(
      "http=foopy1:8080;http=foopy2:8080;http=foopy3.8080;http=foopy4:8080");
  config.set_auto_detect(false);

  ProxyList proxy_list;
  std::vector<ProxyServer> additional_bad_proxies;
  for (const ProxyServer& proxy_server :
       config.proxy_rules().proxies_for_http.GetAll()) {
    proxy_list.AddProxyServer(proxy_server);
    if (proxy_server == config.proxy_rules().proxies_for_http.Get())
      continue;

    additional_bad_proxies.push_back(proxy_server);
  }

  EXPECT_EQ(3u, additional_bad_proxies.size());

  ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                       nullptr, nullptr);
  ProxyInfo proxy_info;
  proxy_info.UseProxyList(proxy_list);
  const ProxyRetryInfoMap& retry_info = service.proxy_retry_info();
  service.MarkProxiesAsBadUntil(proxy_info, base::TimeDelta::FromSeconds(1),
                                additional_bad_proxies, NetLogWithSource());
  ASSERT_EQ(4u, retry_info.size());
  for (const ProxyServer& proxy_server :
       config.proxy_rules().proxies_for_http.GetAll()) {
    ProxyRetryInfoMap::const_iterator i =
        retry_info.find(proxy_server.host_port_pair().ToString());
    ASSERT_TRUE(i != retry_info.end());
  }
}

TEST_F(ProxyServiceTest, PerProtocolProxyTests) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("http=foopy1:8080;https=foopy2:8080");
  config.set_auto_detect(false);
  {
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("http://www.msn.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());
  }
  {
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("ftp://ftp.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(info.is_direct());
    EXPECT_EQ("direct://", info.proxy_server().ToURI());
  }
  {
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("https://webbranch.techcu.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("foopy2:8080", info.proxy_server().ToURI());
  }
  {
    config.proxy_rules().ParseFromString("foopy1:8080");
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("http://www.microsoft.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());
  }
}

TEST_F(ProxyServiceTest, ProxyConfigSourcePropagates) {
  // Test that the proxy config source is set correctly when resolving proxies
  // using manual proxy rules. Namely, the config source should only be set if
  // any of the rules were applied.
  {
    ProxyConfig config;
    config.set_source(PROXY_CONFIG_SOURCE_TEST);
    config.proxy_rules().ParseFromString("https=foopy2:8080");
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("http://www.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    ASSERT_THAT(rv, IsOk());
    // Should be SOURCE_TEST, even if there are no HTTP proxies configured.
    EXPECT_EQ(PROXY_CONFIG_SOURCE_TEST, info.config_source());
  }
  {
    ProxyConfig config;
    config.set_source(PROXY_CONFIG_SOURCE_TEST);
    config.proxy_rules().ParseFromString("https=foopy2:8080");
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("https://www.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    ASSERT_THAT(rv, IsOk());
    // Used the HTTPS proxy. So source should be TEST.
    EXPECT_EQ(PROXY_CONFIG_SOURCE_TEST, info.config_source());
  }
  {
    ProxyConfig config;
    config.set_source(PROXY_CONFIG_SOURCE_TEST);
    ProxyService service(base::MakeUnique<MockProxyConfigService>(config),
                         nullptr, nullptr);
    GURL test_url("http://www.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    ASSERT_THAT(rv, IsOk());
    // ProxyConfig is empty. Source should still be TEST.
    EXPECT_EQ(PROXY_CONFIG_SOURCE_TEST, info.config_source());
  }
}

// If only HTTP and a SOCKS proxy are specified, check if ftp/https queries
// fall back to the SOCKS proxy.
TEST_F(ProxyServiceTest, DefaultProxyFallbackToSOCKS) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("http=foopy1:8080;socks=foopy2:1080");
  config.set_auto_detect(false);
  EXPECT_EQ(ProxyConfig::ProxyRules::TYPE_PROXY_PER_SCHEME,
            config.proxy_rules().type);

  {
    ProxyService service(base::WrapUnique(new MockProxyConfigService(config)),
                         nullptr, nullptr);
    GURL test_url("http://www.msn.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());
  }
  {
    ProxyService service(base::WrapUnique(new MockProxyConfigService(config)),
                         nullptr, nullptr);
    GURL test_url("ftp://ftp.google.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("socks4://foopy2:1080", info.proxy_server().ToURI());
  }
  {
    ProxyService service(base::WrapUnique(new MockProxyConfigService(config)),
                         nullptr, nullptr);
    GURL test_url("https://webbranch.techcu.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("socks4://foopy2:1080", info.proxy_server().ToURI());
  }
  {
    ProxyService service(base::WrapUnique(new MockProxyConfigService(config)),
                         nullptr, nullptr);
    GURL test_url("unknown://www.microsoft.com");
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service.ResolveProxy(test_url, std::string(), &info,
                                  callback.callback(), nullptr, nullptr,
                                  NetLogWithSource());
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(info.is_direct());
    EXPECT_EQ("socks4://foopy2:1080", info.proxy_server().ToURI());
  }
}

// Test cancellation of an in-progress request.
TEST_F(ProxyServiceTest, CancelInProgressRequest) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  const GURL url3("http://request3");
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start 3 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv =
      service.ResolveProxy(url1, std::string(), &info1, callback1.callback(),
                           nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Successfully initialize the PAC script.
  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  GetPendingJobsForURLs(resolver, url1);

  ProxyInfo info2;
  TestCompletionCallback callback2;
  ProxyService::PacRequest* request2;
  rv = service.ResolveProxy(url2, std::string(), &info2, callback2.callback(),
                            &request2, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  GetPendingJobsForURLs(resolver, url1, url2);

  ProxyInfo info3;
  TestCompletionCallback callback3;
  rv = service.ResolveProxy(url3, std::string(), &info3, callback3.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  GetPendingJobsForURLs(resolver, url1, url2, url3);

  // Cancel the second request
  service.CancelPacRequest(request2);

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url3);

  // Complete the two un-cancelled jobs.
  // We complete the last one first, just to mix it up a bit.
  jobs[url3]->results()->UseNamedProxy("request3:80");
  jobs[url3]->CompleteNow(OK);  // dsaadsasd

  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  EXPECT_EQ(OK, callback1.WaitForResult());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  EXPECT_FALSE(callback2.have_result());  // Cancelled.
  GetCancelledJobsForURLs(resolver, url2);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ("request3:80", info3.proxy_server().ToURI());
}

// Test the initial PAC download for resolver that expects bytes.
TEST_F(ProxyServiceTest, InitialPACScriptDownload) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  const GURL url3("http://request3");
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 3 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  ProxyService::PacRequest* request1;
  int rv =
      service.ResolveProxy(url1, std::string(), &info1, callback1.callback(),
                           &request1, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  ProxyInfo info2;
  TestCompletionCallback callback2;
  ProxyService::PacRequest* request2;
  rv = service.ResolveProxy(url2, std::string(), &info2, callback2.callback(),
                            &request2, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info3;
  TestCompletionCallback callback3;
  ProxyService::PacRequest* request3;
  rv = service.ResolveProxy(url3, std::string(), &info3, callback3.callback(),
                            &request3, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  EXPECT_EQ(LOAD_STATE_DOWNLOADING_PROXY_SCRIPT,
            service.GetLoadState(request1));
  EXPECT_EQ(LOAD_STATE_DOWNLOADING_PROXY_SCRIPT,
            service.GetLoadState(request2));
  EXPECT_EQ(LOAD_STATE_DOWNLOADING_PROXY_SCRIPT,
            service.GetLoadState(request3));

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, it will have been sent to the proxy
  // resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2, url3);

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, service.GetLoadState(request1));
  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, service.GetLoadState(request2));
  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, service.GetLoadState(request3));

  // Complete all the jobs (in some order).

  jobs[url3]->results()->UseNamedProxy("request3:80");
  jobs[url3]->CompleteNow(OK);

  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  jobs[url2]->results()->UseNamedProxy("request2:80");
  jobs[url2]->CompleteNow(OK);

  // Complete and verify that jobs ran as expected.
  EXPECT_EQ(OK, callback1.WaitForResult());
  // ProxyResolver::GetProxyForURL() to take a std::unique_ptr<Request>* rather
  // than a RequestHandle* (patchset #11 id:200001 of
  // https://codereview.chromium.org/1439053002/ )
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());
  EXPECT_FALSE(info1.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info1.proxy_resolve_end_time().is_null());
  EXPECT_LE(info1.proxy_resolve_start_time(), info1.proxy_resolve_end_time());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
  EXPECT_FALSE(info2.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info2.proxy_resolve_end_time().is_null());
  EXPECT_LE(info2.proxy_resolve_start_time(), info2.proxy_resolve_end_time());

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ("request3:80", info3.proxy_server().ToURI());
  EXPECT_FALSE(info3.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info3.proxy_resolve_end_time().is_null());
  EXPECT_LE(info3.proxy_resolve_start_time(), info3.proxy_resolve_end_time());
}

// Test changing the ProxyScriptFetcher while PAC download is in progress.
TEST_F(ProxyServiceTest, ChangeScriptFetcherWhilePACDownloadInProgress) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 2 jobs.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv =
      service.ResolveProxy(url1, std::string(), &info1, callback1.callback(),
                           nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(url2, std::string(), &info2, callback2.callback(),
                            nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.

  // We now change out the ProxyService's script fetcher. We should restart
  // the initialization with the new fetcher.

  fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, it will have been sent to the proxy
  // resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  GetPendingJobsForURLs(resolver, url1, url2);
}

// Test cancellation of a request, while the PAC script is being fetched.
TEST_F(ProxyServiceTest, CancelWhilePACFetching) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 3 requests.
  ProxyInfo info1;
  TestCompletionCallback callback1;
  ProxyService::PacRequest* request1;
  BoundTestNetLog log1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), &request1, nullptr,
                                log1.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  ProxyInfo info2;
  TestCompletionCallback callback2;
  ProxyService::PacRequest* request2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), &request2, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info3;
  TestCompletionCallback callback3;
  rv = service.ResolveProxy(GURL("http://request3"), std::string(), &info3,
                            callback3.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // Cancel the first 2 jobs.
  service.CancelPacRequest(request1);
  service.CancelPacRequest(request2);

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, it will have been sent to the
  // proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request3"), resolver.pending_jobs()[0]->url());

  // Complete all the jobs.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request3:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ("request3:80", info3.proxy_server().ToURI());

  EXPECT_TRUE(resolver.cancelled_jobs().empty());

  EXPECT_FALSE(callback1.have_result());  // Cancelled.
  EXPECT_FALSE(callback2.have_result());  // Cancelled.

  TestNetLogEntry::List entries1;
  log1.GetEntries(&entries1);

  // Check the NetLog for request 1 (which was cancelled) got filled properly.
  EXPECT_EQ(4u, entries1.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries1, 0, NetLogEventType::PROXY_SERVICE));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries1, 1, NetLogEventType::PROXY_SERVICE_WAITING_FOR_INIT_PAC));
  // Note that PROXY_SERVICE_WAITING_FOR_INIT_PAC is never completed before
  // the cancellation occured.
  EXPECT_TRUE(LogContainsEvent(entries1, 2, NetLogEventType::CANCELLED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(entries1, 3, NetLogEventType::PROXY_SERVICE));
}

// Test that if auto-detect fails, we fall-back to the custom pac.
TEST_F(ProxyServiceTest, FallbackFromAutodetectToCustomPac) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");  // Won't be used.

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 2 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv =
      service.ResolveProxy(url1, std::string(), &info1, callback1.callback(),
                           nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info2;
  TestCompletionCallback callback2;
  ProxyService::PacRequest* request2;
  rv = service.ResolveProxy(url2, std::string(), &info2, callback2.callback(),
                            &request2, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // It should be trying to auto-detect first -- FAIL the autodetect during
  // the script download.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Next it should be trying the custom PAC url.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // Now finally, the pending jobs should have been sent to the resolver
  // (which was initialized with custom PAC script).

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2);

  // Complete the pending jobs.
  jobs[url2]->results()->UseNamedProxy("request2:80");
  jobs[url2]->CompleteNow(OK);
  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  // Verify that jobs ran as expected.
  EXPECT_EQ(OK, callback1.WaitForResult());
  // ProxyResolver::GetProxyForURL() to take a std::unique_ptr<Request>* rather
  // than a RequestHandle* (patchset #11 id:200001 of
  // https://codereview.chromium.org/1439053002/ )
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());
  EXPECT_FALSE(info1.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info1.proxy_resolve_end_time().is_null());
  EXPECT_LE(info1.proxy_resolve_start_time(), info1.proxy_resolve_end_time());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
  EXPECT_FALSE(info2.proxy_resolve_start_time().is_null());
  EXPECT_FALSE(info2.proxy_resolve_end_time().is_null());
  EXPECT_LE(info2.proxy_resolve_start_time(), info2.proxy_resolve_end_time());
}

// This is the same test as FallbackFromAutodetectToCustomPac, except
// the auto-detect script fails parsing rather than downloading.
TEST_F(ProxyServiceTest, FallbackFromAutodetectToCustomPac2) {
  const GURL url1("http://request1");
  const GURL url2("http://request2");
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");  // Won't be used.

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 2 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv =
      service.ResolveProxy(url1, std::string(), &info1, callback1.callback(),
                           nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info2;
  TestCompletionCallback callback2;
  ProxyService::PacRequest* request2;
  rv = service.ResolveProxy(url2, std::string(), &info2, callback2.callback(),
                            &request2, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // It should be trying to auto-detect first -- succeed the download.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, "invalid-script-contents");

  // The script contents passed failed basic verification step (since didn't
  // contain token FindProxyForURL), so it was never passed to the resolver.

  // Next it should be trying the custom PAC url.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // Now finally, the pending jobs should have been sent to the resolver
  // (which was initialized with custom PAC script).

  JobMap jobs = GetPendingJobsForURLs(resolver, url1, url2);

  // Complete the pending jobs.
  jobs[url2]->results()->UseNamedProxy("request2:80");
  jobs[url2]->CompleteNow(OK);
  jobs[url1]->results()->UseNamedProxy("request1:80");
  jobs[url1]->CompleteNow(OK);

  // Verify that jobs ran as expected.
  EXPECT_EQ(OK, callback1.WaitForResult());
  // ProxyResolver::GetProxyForURL() to take a std::unique_ptr<Request>* rather
  // than a RequestHandle* (patchset #11 id:200001 of
  // https://codereview.chromium.org/1439053002/ )
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
}

// Test that if all of auto-detect, a custom PAC script, and manual settings
// are given, then we will try them in that order.
TEST_F(ProxyServiceTest, FallbackFromAutodetectToCustomToManual) {
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 2 jobs.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ProxyInfo info2;
  TestCompletionCallback callback2;
  ProxyService::PacRequest* request2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), &request2, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // It should be trying to auto-detect first -- fail the download.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Next it should be trying the custom PAC url -- fail the download.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Since we never managed to initialize a resolver, nothing should have been
  // sent to it.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // Verify that jobs ran as expected -- they should have fallen back to
  // the manual proxy configuration for HTTP urls.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("foopy:80", info1.proxy_server().ToURI());

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("foopy:80", info2.proxy_server().ToURI());
}

// Test that the bypass rules are NOT applied when using autodetect.
TEST_F(ProxyServiceTest, BypassDoesntApplyToPac) {
  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://foopy/proxy.pac"));
  config.proxy_rules().ParseFromString("http=foopy:80");  // Not used.
  config.proxy_rules().bypass_rules.ParseFromString("www.google.com");

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 requests.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://www.google.com"), std::string(),
                                &info1, callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // It should be trying to auto-detect first -- succeed the download.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://wpad/wpad.dat"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://www.google.com"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Verify that request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // Start another request, it should pickup the bypass item.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://www.google.com"), std::string(),
                            &info2, callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://www.google.com"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
}

// Delete the ProxyService while InitProxyResolver has an outstanding
// request to the script fetcher. When run under valgrind, should not
// have any memory errors (used to be that the ProxyScriptFetcher was
// being deleted prior to the InitProxyResolver).
TEST_F(ProxyServiceTest, DeleteWhileInitProxyResolverHasOutstandingFetch) {
  ProxyConfig config =
    ProxyConfig::CreateFromCustomPacURL(GURL("http://foopy/proxy.pac"));

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://www.google.com"), std::string(),
                                &info1, callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that nothing has been sent to the proxy resolver factory yet.
  ASSERT_EQ(0u, factory->pending_requests().size());

  // InitProxyResolver should have issued a request to the ProxyScriptFetcher
  // and be waiting on that to complete.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
}

// Delete the ProxyService while InitProxyResolver has an outstanding
// request to the proxy resolver. When run under valgrind, should not
// have any memory errors (used to be that the ProxyResolver was
// being deleted prior to the InitProxyResolver).
TEST_F(ProxyServiceTest, DeleteWhileInitProxyResolverHasOutstandingSet) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  TestCompletionCallback callback;
  int rv = service.ResolveProxy(url, std::string(), &info, callback.callback(),
                                nullptr, nullptr, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_EQ(GURL("http://foopy/proxy.pac"),
            factory->pending_requests()[0]->script_data()->url());
}

TEST_F(ProxyServiceTest, ResetProxyConfigService) {
  ProxyConfig config1;
  config1.proxy_rules().ParseFromString("foopy1:8080");
  config1.set_auto_detect(false);
  ProxyService service(base::MakeUnique<MockProxyConfigService>(config1),
                       nullptr, nullptr);

  ProxyInfo info;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("foopy1:8080", info.proxy_server().ToURI());

  ProxyConfig config2;
  config2.proxy_rules().ParseFromString("foopy2:8080");
  config2.set_auto_detect(false);
  service.ResetConfigService(base::MakeUnique<MockProxyConfigService>(config2));
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("foopy2:8080", info.proxy_server().ToURI());
}

// Test that when going from a configuration that required PAC to one
// that does NOT, we unset the variable |should_use_proxy_resolver_|.
TEST_F(ProxyServiceTest, UpdateConfigFromPACToDirect) {
  ProxyConfig config = ProxyConfig::CreateAutoDetect();

  MockProxyConfigService* config_service = new MockProxyConfigService(config);
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);
  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://www.google.com"), std::string(),
                                &info1, callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Successfully set the autodetect script.
  EXPECT_EQ(ProxyResolverScriptData::TYPE_AUTO_DETECT,
            factory->pending_requests()[0]->script_data()->type());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // Complete the pending request.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Verify that request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // Force the ProxyService to pull down a new proxy configuration.
  // (Even though the configuration isn't old/bad).
  //
  // This new configuration no longer has auto_detect set, so
  // jobs should complete synchronously now as direct-connect.
  config_service->SetConfig(ProxyConfig::CreateDirect());

  // Start another request -- the effective configuration has changed.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://www.google.com"), std::string(),
                            &info2, callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(info2.is_direct());
}

TEST_F(ProxyServiceTest, NetworkChangeTriggersPacRefetch) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  TestNetLog log;

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), &log);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::MakeUnique<DoNothingDhcpProxyScriptFetcher>());

  // Disable the "wait after IP address changes" hack, so this unit-test can
  // complete quickly.
  service.set_stall_proxy_auto_config_delay(base::TimeDelta());

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, the request will have been sent to
  // the proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request1"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // Now simluate a change in the network. The ProxyConfigService is still
  // going to return the same PAC URL as before, but this URL needs to be
  // refetched on the new network.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // This second request should have triggered the re-download of the PAC
  // script (since we marked the network as having changed).
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // Simulate the PAC script fetch as having completed (this time with
  // different data).
  fetcher->NotifyFetchCompletion(OK, kValidPacScript2);

  // Now that the PAC script is downloaded, the second request will have been
  // sent to the proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript2),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());

  // Check that the expected events were output to the log stream. In particular
  // PROXY_CONFIG_CHANGED should have only been emitted once (for the initial
  // setup), and NOT a second time when the IP address changed.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_TRUE(LogContainsEntryWithType(entries, 0,
                                       NetLogEventType::PROXY_CONFIG_CHANGED));
  ASSERT_EQ(9u, entries.size());
  for (size_t i = 1; i < entries.size(); ++i)
    EXPECT_NE(NetLogEventType::PROXY_CONFIG_CHANGED, entries[i].type);
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch fails due
// to a network error, we will eventually re-configure the service to use the
// script once it becomes available.
TEST_F(ProxyServiceTest, PACScriptRefetchAfterFailure) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ProxyService::set_pac_script_poll_policy(&poll_policy);

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  //
  // We simulate a failed download attempt, the proxy service should now
  // fall-back to DIRECT connections.
  fetcher->NotifyFetchCompletion(ERR_FAILED, std::string());

  ASSERT_TRUE(factory->pending_requests().empty());

  // Wait for completion callback, and verify it used DIRECT.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(info1.is_direct());

  // At this point we have initialized the proxy service using a PAC script,
  // however it failed and fell-back to DIRECT.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher->WaitUntilFetch();

  ASSERT_TRUE(factory->pending_requests().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). This time we will simulate a successful
  // download of the script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  base::RunLoop().RunUntilIdle();

  // Now that the PAC script is downloaded, it should be used to initialize the
  // ProxyResolver. Simulate a successful parse.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // At this point the ProxyService should have re-configured itself to use the
  // PAC script (thereby recovering from the initial fetch failure). We will
  // verify that the next Resolve request uses the resolver rather than
  // DIRECT.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that it was sent to the resolver.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch succeeds,
// however at a later time its *contents* change, we will eventually
// re-configure the service to use the new script.
TEST_F(ProxyServiceTest, PACScriptRefetchAfterContentChange) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ProxyService::set_pac_script_poll_policy(&poll_policy);

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, the request will have been sent to
  // the proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request1"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // At this point we have initialized the proxy service using a PAC script.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher->WaitUntilFetch();

  ASSERT_TRUE(factory->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). This time we will simulate a successful
  // download of a DIFFERENT script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, kValidPacScript2);

  base::RunLoop().RunUntilIdle();

  // Now that the PAC script is downloaded, it should be used to initialize the
  // ProxyResolver. Simulate a successful parse.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript2),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  // At this point the ProxyService should have re-configured itself to use the
  // new PAC script.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that it was sent to the resolver.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch succeeds
// and so does the next poll, however the contents of the downloaded script
// have NOT changed, then we do not bother to re-initialize the proxy resolver.
TEST_F(ProxyServiceTest, PACScriptRefetchAfterContentUnchanged) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ProxyService::set_pac_script_poll_policy(&poll_policy);

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, the request will have been sent to
  // the proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request1"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // At this point we have initialized the proxy service using a PAC script.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher->WaitUntilFetch();

  ASSERT_TRUE(factory->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). We will simulate the same response as
  // last time (i.e. the script is unchanged).
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(factory->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // At this point the ProxyService is still running the same PAC script as
  // before.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Check that it was sent to the resolver.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());

  // Complete the pending second request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());
}

// This test verifies that the PAC script specified by the settings is
// periodically polled for changes. Specifically, if the initial fetch succeeds,
// however at a later time it starts to fail, we should re-configure the
// ProxyService to stop using that PAC script.
TEST_F(ProxyServiceTest, PACScriptRefetchAfterSuccess) {
  // Change the retry policy to wait a mere 1 ms before retrying, so the test
  // runs quickly.
  ImmediatePollPolicy poll_policy;
  ProxyService::set_pac_script_poll_policy(&poll_policy);

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, the request will have been sent to
  // the proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request1"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // At this point we have initialized the proxy service using a PAC script.
  //
  // A background task to periodically re-check the PAC script for validity will
  // have been started. We will now wait for the next download attempt to start.
  //
  // Note that we shouldn't have to wait long here, since our test enables a
  // special unit-test mode.
  fetcher->WaitUntilFetch();

  ASSERT_TRUE(factory->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Make sure that our background checker is trying to download the expected
  // PAC script (same one as before). This time we will simulate a failure
  // to download the script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());
  fetcher->NotifyFetchCompletion(ERR_FAILED, std::string());

  base::RunLoop().RunUntilIdle();

  // At this point the ProxyService should have re-configured itself to use
  // DIRECT connections rather than the given proxy resolver.

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info2.is_direct());
}

// Tests that the code which decides at what times to poll the PAC
// script follows the expected policy.
TEST_F(ProxyServiceTest, PACScriptPollingPolicy) {
  // Retrieve the internal polling policy implementation used by ProxyService.
  std::unique_ptr<ProxyService::PacPollPolicy> policy =
      ProxyService::CreateDefaultPacPollPolicy();

  int error;
  ProxyService::PacPollPolicy::Mode mode;
  const base::TimeDelta initial_delay = base::TimeDelta::FromMilliseconds(-1);
  base::TimeDelta delay = initial_delay;

  // --------------------------------------------------
  // Test the poll sequence in response to a failure.
  // --------------------------------------------------
  error = ERR_NAME_NOT_RESOLVED;

  // Poll #0
  mode = policy->GetNextDelay(error, initial_delay, &delay);
  EXPECT_EQ(8, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_USE_TIMER, mode);

  // Poll #1
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(32, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);

  // Poll #2
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(120, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);

  // Poll #3
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(14400, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);

  // Poll #4
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(14400, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);

  // --------------------------------------------------
  // Test the poll sequence in response to a success.
  // --------------------------------------------------
  error = OK;

  // Poll #0
  mode = policy->GetNextDelay(error, initial_delay, &delay);
  EXPECT_EQ(43200, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);

  // Poll #1
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(43200, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);

  // Poll #2
  mode = policy->GetNextDelay(error, delay, &delay);
  EXPECT_EQ(43200, delay.InSeconds());
  EXPECT_EQ(ProxyService::PacPollPolicy::MODE_START_AFTER_ACTIVITY, mode);
}

// This tests the polling of the PAC script. Specifically, it tests that
// polling occurs in response to user activity.
TEST_F(ProxyServiceTest, PACScriptRefetchAfterActivity) {
  ImmediateAfterActivityPollPolicy poll_policy;
  ProxyService::set_pac_script_poll_policy(&poll_policy);

  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(true);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  MockProxyScriptFetcher* fetcher = new MockProxyScriptFetcher;
  service.SetProxyScriptFetchers(
      fetcher, base::WrapUnique(new DoNothingDhcpProxyScriptFetcher()));

  // Start 1 request.

  ProxyInfo info1;
  TestCompletionCallback callback1;
  int rv = service.ResolveProxy(GURL("http://request1"), std::string(), &info1,
                                callback1.callback(), nullptr, nullptr,
                                NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The first request should have triggered initial download of PAC script.
  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // Nothing has been sent to the factory yet.
  EXPECT_TRUE(factory->pending_requests().empty());

  // At this point the ProxyService should be waiting for the
  // ProxyScriptFetcher to invoke its completion callback, notifying it of
  // PAC script download completion.
  fetcher->NotifyFetchCompletion(OK, kValidPacScript1);

  // Now that the PAC script is downloaded, the request will have been sent to
  // the proxy resolver.
  EXPECT_EQ(ASCIIToUTF16(kValidPacScript1),
            factory->pending_requests()[0]->script_data()->utf16());
  factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request1"), resolver.pending_jobs()[0]->url());

  // Complete the pending request.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request1:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  // Wait for completion callback, and verify that the request ran as expected.
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ("request1:80", info1.proxy_server().ToURI());

  // At this point we have initialized the proxy service using a PAC script.
  // Our PAC poller is set to update ONLY in response to network activity,
  // (i.e. another call to ResolveProxy()).

  ASSERT_FALSE(fetcher->has_pending_request());
  ASSERT_TRUE(factory->pending_requests().empty());
  ASSERT_TRUE(resolver.pending_jobs().empty());

  // Start a second request.
  ProxyInfo info2;
  TestCompletionCallback callback2;
  rv = service.ResolveProxy(GURL("http://request2"), std::string(), &info2,
                            callback2.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // This request should have sent work to the resolver; complete it.
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(GURL("http://request2"), resolver.pending_jobs()[0]->url());
  resolver.pending_jobs()[0]->results()->UseNamedProxy("request2:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ("request2:80", info2.proxy_server().ToURI());

  // In response to getting that resolve request, the poller should have
  // started the next poll, and made it as far as to request the download.

  EXPECT_TRUE(fetcher->has_pending_request());
  EXPECT_EQ(GURL("http://foopy/proxy.pac"), fetcher->pending_request_url());

  // This time we will fail the download, to simulate a PAC script change.
  fetcher->NotifyFetchCompletion(ERR_FAILED, std::string());

  // Drain the message loop, so ProxyService is notified of the change
  // and has a chance to re-configure itself.
  base::RunLoop().RunUntilIdle();

  // Start a third request -- this time we expect to get a direct connection
  // since the PAC script poller experienced a failure.
  ProxyInfo info3;
  TestCompletionCallback callback3;
  rv = service.ResolveProxy(GURL("http://request3"), std::string(), &info3,
                            callback3.callback(), nullptr, nullptr,
                            NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(info3.is_direct());
}

// Test that the synchronous resolution fails when a PAC script is active.
TEST_F(ProxyServiceTest, SynchronousWithPAC) {
  MockProxyConfigService* config_service =
      new MockProxyConfigService("http://foopy/proxy.pac");

  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(config_service),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  info.UseDirect();
  BoundTestNetLog log;

  bool synchronous_success = service.TryResolveProxySynchronously(
      url, std::string(), &info, nullptr, log.bound());
  EXPECT_FALSE(synchronous_success);

  // |info| should not have been modified.
  EXPECT_TRUE(info.is_direct());
}

// Test that synchronous results are returned correctly if a fixed proxy
// configuration is active.
TEST_F(ProxyServiceTest, SynchronousWithFixedConfiguration) {
  ProxyConfig config;
  config.proxy_rules().ParseFromString("foopy1:8080");
  config.set_auto_detect(false);

  MockAsyncProxyResolverFactory* factory =
      new MockAsyncProxyResolverFactory(false);

  ProxyService service(base::WrapUnique(new MockProxyConfigService(config)),
                       base::WrapUnique(factory), nullptr);

  GURL url("http://www.google.com/");

  ProxyInfo info;
  BoundTestNetLog log;

  bool synchronous_success = service.TryResolveProxySynchronously(
      url, std::string(), &info, nullptr, log.bound());
  EXPECT_TRUE(synchronous_success);
  EXPECT_FALSE(info.is_direct());
  EXPECT_EQ("foopy1", info.proxy_server().host_port_pair().host());

  // No request should have been queued.
  EXPECT_EQ(0u, factory->pending_requests().size());
}

// Helper class to exercise URL sanitization using the different policies. This
// works by submitted URLs to the ProxyService. In turn the ProxyService
// sanitizes the URL and then passes it along to the ProxyResolver. This helper
// returns the URL seen by the ProxyResolver.
class SanitizeUrlHelper {
 public:
  SanitizeUrlHelper() {
    std::unique_ptr<MockProxyConfigService> config_service(
        new MockProxyConfigService("http://foopy/proxy.pac"));

    factory = new MockAsyncProxyResolverFactory(false);

    service_.reset(new ProxyService(std::move(config_service),
                                    base::WrapUnique(factory), nullptr));

    // Do an initial request to initialize the service (configure the PAC
    // script).
    GURL url("http://example.com");

    ProxyInfo info;
    TestCompletionCallback callback;
    int rv =
        service_->ResolveProxy(url, std::string(), &info, callback.callback(),
                               nullptr, nullptr, NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    // First step is to download the PAC script.
    EXPECT_EQ(GURL("http://foopy/proxy.pac"),
              factory->pending_requests()[0]->script_data()->url());
    factory->pending_requests()[0]->CompleteNowWithForwarder(OK, &resolver);

    EXPECT_EQ(1u, resolver.pending_jobs().size());
    EXPECT_EQ(url, resolver.pending_jobs()[0]->url());

    // Complete the request.
    resolver.pending_jobs()[0]->results()->UsePacString("DIRECT");
    resolver.pending_jobs()[0]->CompleteNow(OK);
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(info.is_direct());
  }

  // Changes the URL sanitization policy for the underlying ProxyService. This
  // will affect subsequent calls to SanitizeUrl.
  void SetSanitizeUrlPolicy(ProxyService::SanitizeUrlPolicy policy) {
    service_->set_sanitize_url_policy(policy);
  }

  // Makes a proxy resolution request through the ProxyService, and returns the
  // URL that was submitted to the Proxy Resolver.
  GURL SanitizeUrl(const GURL& raw_url) {
    // Issue a request and see what URL is sent to the proxy resolver.
    ProxyInfo info;
    TestCompletionCallback callback;
    int rv = service_->ResolveProxy(raw_url, std::string(), &info,
                                    callback.callback(), nullptr, nullptr,
                                    NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    EXPECT_EQ(1u, resolver.pending_jobs().size());

    GURL sanitized_url = resolver.pending_jobs()[0]->url();

    // Complete the request.
    resolver.pending_jobs()[0]->results()->UsePacString("DIRECT");
    resolver.pending_jobs()[0]->CompleteNow(OK);
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(info.is_direct());

    return sanitized_url;
  }

  // Changes the ProxyService's URL sanitization policy and then sanitizes
  // |raw_url|.
  GURL SanitizeUrl(const GURL& raw_url,
                   ProxyService::SanitizeUrlPolicy policy) {
    service_->set_sanitize_url_policy(policy);
    return SanitizeUrl(raw_url);
  }

 private:
  MockAsyncProxyResolver resolver;
  MockAsyncProxyResolverFactory* factory;
  std::unique_ptr<ProxyService> service_;
};

TEST_F(ProxyServiceTest, SanitizeUrlDefaultsToSafe) {
  SanitizeUrlHelper helper;

  // Without changing the URL sanitization policy, the default should be to
  // strip https:// URLs.
  EXPECT_EQ(GURL("https://example.com/"),
            helper.SanitizeUrl(
                GURL("https://foo:bar@example.com/foo/bar/baz?hello#sigh")));
}

// Tests URL sanitization with input URLs that have a // non-cryptographic
// scheme (i.e. http://). The sanitized result is consistent regardless of the
// stripping mode selected.
TEST_F(ProxyServiceTest, SanitizeUrlForPacScriptNonCryptographic) {
  const struct {
    const char* raw_url;
    const char* sanitized_url;
  } kTests[] = {
      // Embedded identity is stripped.
      {
          "http://foo:bar@example.com/", "http://example.com/",
      },
      {
          "ftp://foo:bar@example.com/", "ftp://example.com/",
      },
      {
          "ftp://example.com/some/path/here",
          "ftp://example.com/some/path/here",
      },
      // Reference fragment is stripped.
      {
          "http://example.com/blah#hello", "http://example.com/blah",
      },
      // Query parameters are NOT stripped.
      {
          "http://example.com/foo/bar/baz?hello",
          "http://example.com/foo/bar/baz?hello",
      },
      // Fragment is stripped, but path and query are left intact.
      {
          "http://foo:bar@example.com/foo/bar/baz?hello#sigh",
          "http://example.com/foo/bar/baz?hello",
      },
      // Port numbers are not affected.
      {
          "http://example.com:88/hi", "http://example.com:88/hi",
      },
  };

  SanitizeUrlHelper helper;

  for (const auto& test : kTests) {
    // The result of SanitizeUrlForPacScript() is the same regardless of the
    // second parameter (sanitization mode), since the input URLs do not use a
    // cryptographic scheme.
    GURL raw_url(test.raw_url);
    ASSERT_TRUE(raw_url.is_valid());
    EXPECT_FALSE(raw_url.SchemeIsCryptographic());

    EXPECT_EQ(
        GURL(test.sanitized_url),
        helper.SanitizeUrl(raw_url, ProxyService::SanitizeUrlPolicy::UNSAFE));

    EXPECT_EQ(
        GURL(test.sanitized_url),
        helper.SanitizeUrl(raw_url, ProxyService::SanitizeUrlPolicy::SAFE));
  }
}

// Tests URL sanitization using input URLs that have a cryptographic schemes
// (i.e. https://). The sanitized result differs depending on the sanitization
// mode chosen.
TEST_F(ProxyServiceTest, SanitizeUrlForPacScriptCryptographic) {
  const struct {
    // Input URL.
    const char* raw_url;

    // Output URL when stripping of cryptographic URLs is disabled.
    const char* sanitized_url_unstripped;

    // Output URL when stripping of cryptographic URLs is enabled.
    const char* sanitized_url;
  } kTests[] = {
      // Embedded identity is always stripped.
      {
          "https://foo:bar@example.com/", "https://example.com/",
          "https://example.com/",
      },
      // Fragments are always stripped, but stripping path is conditional on the
      // mode.
      {
          "https://example.com/blah#hello", "https://example.com/blah",
          "https://example.com/",
      },
      // Stripping the query is conditional on the mode.
      {
          "https://example.com/?hello", "https://example.com/?hello",
          "https://example.com/",
      },
      // The embedded identity and fragment is always stripped, however path and
      // query are conditional on the stripping mode.
      {
          "https://foo:bar@example.com/foo/bar/baz?hello#sigh",
          "https://example.com/foo/bar/baz?hello", "https://example.com/",
      },
      // The URL's port should not be stripped.
      {
          "https://example.com:88/hi", "https://example.com:88/hi",
          "https://example.com:88/",
      },
      // Try a wss:// URL, to make sure it also strips (is is also a
      // cryptographic URL).
      {
          "wss://example.com:88/hi", "wss://example.com:88/hi",
          "wss://example.com:88/",
      },
  };

  SanitizeUrlHelper helper;

  for (const auto& test : kTests) {
    GURL raw_url(test.raw_url);
    ASSERT_TRUE(raw_url.is_valid());
    EXPECT_TRUE(raw_url.SchemeIsCryptographic());

    EXPECT_EQ(
        GURL(test.sanitized_url_unstripped),
        helper.SanitizeUrl(raw_url, ProxyService::SanitizeUrlPolicy::UNSAFE));

    EXPECT_EQ(
        GURL(test.sanitized_url),
        helper.SanitizeUrl(raw_url, ProxyService::SanitizeUrlPolicy::SAFE));
  }
}

}  // namespace net
