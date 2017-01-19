// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_service_mojo.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/singleton.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/base/network_delegate_impl.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/proxy/dhcp_proxy_script_fetcher.h"
#include "net/proxy/mock_proxy_script_fetcher.h"
#include "net/proxy/mojo_proxy_resolver_factory.h"
#include "net/proxy/mojo_proxy_resolver_factory_impl.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/proxy/proxy_service.h"
#include "net/test/event_waiter.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using net::test::IsOk;

namespace net {

namespace {

const char kPacUrl[] = "http://example.com/proxy.pac";
const char kSimplePacScript[] =
    "function FindProxyForURL(url, host) {\n"
    "  return 'PROXY foo:1234';\n"
    "}";
const char kDnsResolvePacScript[] =
    "function FindProxyForURL(url, host) {\n"
    "  if (dnsResolveEx('example.com') != '1.2.3.4')\n"
    "    return 'DIRECT';\n"
    "  return 'QUIC bar:4321';\n"
    "}";
const char kThrowingPacScript[] =
    "function FindProxyForURL(url, host) {\n"
    "  alert('alert: ' + host);\n"
    "  throw new Error('error: ' + url);\n"
    "}";
const char kThrowingOnLoadPacScript[] =
    "function FindProxyForURL(url, host) {}\n"
    "alert('alert: foo');\n"
    "throw new Error('error: http://foo');";

class TestNetworkDelegate : public NetworkDelegateImpl {
 public:
  enum Event {
    PAC_SCRIPT_ERROR,
  };

  EventWaiter<Event>& event_waiter() { return event_waiter_; }

  void OnPACScriptError(int line_number, const base::string16& error) override;

 private:
  EventWaiter<Event> event_waiter_;
};

void TestNetworkDelegate::OnPACScriptError(int line_number,
                                           const base::string16& error) {
  event_waiter_.NotifyEvent(PAC_SCRIPT_ERROR);
  EXPECT_EQ(3, line_number);
  EXPECT_TRUE(base::UTF16ToUTF8(error).find("error: http://foo") !=
              std::string::npos);
}

void CheckCapturedNetLogEntries(const TestNetLogEntry::List& entries) {
  ASSERT_GT(entries.size(), 2u);
  size_t i = 0;
  // ProxyService records its own NetLog entries, so skip forward until the
  // expected event type.
  while (i < entries.size() &&
         entries[i].type != NetLogEventType::PAC_JAVASCRIPT_ALERT) {
    i++;
  }
  ASSERT_LT(i, entries.size());
  std::string message;
  ASSERT_TRUE(entries[i].GetStringValue("message", &message));
  EXPECT_EQ("alert: foo", message);
  ASSERT_FALSE(entries[i].params->HasKey("line_number"));

  while (i < entries.size() &&
         entries[i].type != NetLogEventType::PAC_JAVASCRIPT_ERROR) {
    i++;
  }
  message.clear();
  ASSERT_TRUE(entries[i].GetStringValue("message", &message));
  EXPECT_THAT(message, testing::HasSubstr("error: http://foo"));
  int line_number = 0;
  ASSERT_TRUE(entries[i].GetIntegerValue("line_number", &line_number));
  EXPECT_EQ(3, line_number);
}

class LoggingMockHostResolver : public MockHostResolver {
 public:
  int Resolve(const RequestInfo& info,
              RequestPriority priority,
              AddressList* addresses,
              const CompletionCallback& callback,
              std::unique_ptr<Request>* out_req,
              const NetLogWithSource& net_log) override {
    net_log.AddEvent(NetLogEventType::HOST_RESOLVER_IMPL_JOB);
    return MockHostResolver::Resolve(info, priority, addresses, callback,
                                     out_req, net_log);
  }
};

class InProcessMojoProxyResolverFactory : public MojoProxyResolverFactory {
 public:
  static InProcessMojoProxyResolverFactory* GetInstance() {
    return base::Singleton<InProcessMojoProxyResolverFactory>::get();
  }

  // Overridden from MojoProxyResolverFactory:
  std::unique_ptr<base::ScopedClosureRunner> CreateResolver(
      const std::string& pac_script,
      mojo::InterfaceRequest<interfaces::ProxyResolver> req,
      interfaces::ProxyResolverFactoryRequestClientPtr client) override {
    factory_->CreateResolver(pac_script, std::move(req), std::move(client));
    return nullptr;
  }

 private:
  InProcessMojoProxyResolverFactory() {
    mojo::MakeStrongBinding(base::MakeUnique<MojoProxyResolverFactoryImpl>(),
                            mojo::MakeRequest(&factory_));
  }
  ~InProcessMojoProxyResolverFactory() override = default;
  friend struct base::DefaultSingletonTraits<InProcessMojoProxyResolverFactory>;

  interfaces::ProxyResolverFactoryPtr factory_;

  DISALLOW_COPY_AND_ASSIGN(InProcessMojoProxyResolverFactory);
};

}  // namespace

class ProxyServiceMojoTest : public testing::Test,
                             public MojoProxyResolverFactory {
 protected:
  void SetUp() override {
    mock_host_resolver_.rules()->AddRule("example.com", "1.2.3.4");

    fetcher_ = new MockProxyScriptFetcher;
    proxy_service_ = CreateProxyServiceUsingMojoFactory(
        this, base::MakeUnique<ProxyConfigServiceFixed>(
                  ProxyConfig::CreateFromCustomPacURL(GURL(kPacUrl))),
        fetcher_, base::MakeUnique<DoNothingDhcpProxyScriptFetcher>(),
        &mock_host_resolver_, &net_log_, &network_delegate_);
  }

  std::unique_ptr<base::ScopedClosureRunner> CreateResolver(
      const std::string& pac_script,
      mojo::InterfaceRequest<interfaces::ProxyResolver> req,
      interfaces::ProxyResolverFactoryRequestClientPtr client) override {
    InProcessMojoProxyResolverFactory::GetInstance()->CreateResolver(
        pac_script, std::move(req), std::move(client));
    return base::MakeUnique<base::ScopedClosureRunner>(
        on_delete_closure_.closure());
  }

  TestNetworkDelegate network_delegate_;
  LoggingMockHostResolver mock_host_resolver_;
  MockProxyScriptFetcher* fetcher_;  // Owned by |proxy_service_|.
  TestNetLog net_log_;
  TestClosure on_delete_closure_;
  std::unique_ptr<ProxyService> proxy_service_;
};

TEST_F(ProxyServiceMojoTest, Basic) {
  ProxyInfo info;
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            proxy_service_->ResolveProxy(GURL("http://foo"), std::string(),
                                         &info, callback.callback(), nullptr,
                                         nullptr, NetLogWithSource()));

  // Proxy script fetcher should have a fetch triggered by the first
  // |ResolveProxy()| request.
  EXPECT_TRUE(fetcher_->has_pending_request());
  EXPECT_EQ(GURL(kPacUrl), fetcher_->pending_request_url());
  fetcher_->NotifyFetchCompletion(OK, kSimplePacScript);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ("PROXY foo:1234", info.ToPacString());
  EXPECT_EQ(0u, mock_host_resolver_.num_resolve());
  proxy_service_.reset();
  on_delete_closure_.WaitForResult();
}

TEST_F(ProxyServiceMojoTest, DnsResolution) {
  ProxyInfo info;
  TestCompletionCallback callback;
  BoundTestNetLog test_net_log;
  EXPECT_EQ(ERR_IO_PENDING,
            proxy_service_->ResolveProxy(GURL("http://foo"), std::string(),
                                         &info, callback.callback(), nullptr,
                                         nullptr, test_net_log.bound()));

  // Proxy script fetcher should have a fetch triggered by the first
  // |ResolveProxy()| request.
  EXPECT_TRUE(fetcher_->has_pending_request());
  EXPECT_EQ(GURL(kPacUrl), fetcher_->pending_request_url());
  fetcher_->NotifyFetchCompletion(OK, kDnsResolvePacScript);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ("QUIC bar:4321", info.ToPacString());
  EXPECT_EQ(1u, mock_host_resolver_.num_resolve());
  proxy_service_.reset();
  on_delete_closure_.WaitForResult();

  TestNetLogEntry::List entries;
  test_net_log.GetEntries(&entries);
  // There should be one entry with type TYPE_HOST_RESOLVER_IMPL_JOB.
  EXPECT_EQ(1, std::count_if(entries.begin(), entries.end(),
                             [](const TestNetLogEntry& entry) {
                               return entry.type ==
                                      NetLogEventType::HOST_RESOLVER_IMPL_JOB;
                             }));
}

TEST_F(ProxyServiceMojoTest, Error) {
  ProxyInfo info;
  TestCompletionCallback callback;
  BoundTestNetLog test_net_log;
  EXPECT_EQ(ERR_IO_PENDING,
            proxy_service_->ResolveProxy(GURL("http://foo"), std::string(),
                                         &info, callback.callback(), nullptr,
                                         nullptr, test_net_log.bound()));

  // Proxy script fetcher should have a fetch triggered by the first
  // |ResolveProxy()| request.
  EXPECT_TRUE(fetcher_->has_pending_request());
  EXPECT_EQ(GURL(kPacUrl), fetcher_->pending_request_url());
  fetcher_->NotifyFetchCompletion(OK, kThrowingPacScript);

  network_delegate_.event_waiter().WaitForEvent(
      TestNetworkDelegate::PAC_SCRIPT_ERROR);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ("DIRECT", info.ToPacString());
  EXPECT_EQ(0u, mock_host_resolver_.num_resolve());

  TestNetLogEntry::List entries;
  test_net_log.GetEntries(&entries);
  CheckCapturedNetLogEntries(entries);
  entries.clear();
  net_log_.GetEntries(&entries);
  CheckCapturedNetLogEntries(entries);
}

TEST_F(ProxyServiceMojoTest, ErrorOnInitialization) {
  ProxyInfo info;
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            proxy_service_->ResolveProxy(GURL("http://foo"), std::string(),
                                         &info, callback.callback(), nullptr,
                                         nullptr, NetLogWithSource()));

  // Proxy script fetcher should have a fetch triggered by the first
  // |ResolveProxy()| request.
  EXPECT_TRUE(fetcher_->has_pending_request());
  EXPECT_EQ(GURL(kPacUrl), fetcher_->pending_request_url());
  fetcher_->NotifyFetchCompletion(OK, kThrowingOnLoadPacScript);

  network_delegate_.event_waiter().WaitForEvent(
      TestNetworkDelegate::PAC_SCRIPT_ERROR);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ("DIRECT", info.ToPacString());
  EXPECT_EQ(0u, mock_host_resolver_.num_resolve());

  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  CheckCapturedNetLogEntries(entries);
}

}  // namespace net
