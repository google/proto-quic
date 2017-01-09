// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_resolver_factory_mojo.h"

#include <list>
#include <map>
#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/stl_util.h"
#include "base/values.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/host_resolver.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/proxy/mojo_proxy_resolver_factory.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_resolver_error_observer.h"
#include "net/proxy/proxy_resolver_script_data.h"
#include "net/test/event_waiter.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kScriptData[] = "FooBarBaz";
const char kExampleUrl[] = "http://www.example.com";

struct CreateProxyResolverAction {
  enum Action {
    COMPLETE,
    DROP_CLIENT,
    DROP_RESOLVER,
    DROP_BOTH,
    WAIT_FOR_CLIENT_DISCONNECT,
    MAKE_DNS_REQUEST,
  };

  static CreateProxyResolverAction ReturnResult(
      const std::string& expected_pac_script,
      Error error) {
    CreateProxyResolverAction result;
    result.expected_pac_script = expected_pac_script;
    result.error = error;
    return result;
  }

  static CreateProxyResolverAction DropClient(
      const std::string& expected_pac_script) {
    CreateProxyResolverAction result;
    result.expected_pac_script = expected_pac_script;
    result.action = DROP_CLIENT;
    return result;
  }

  static CreateProxyResolverAction DropResolver(
      const std::string& expected_pac_script) {
    CreateProxyResolverAction result;
    result.expected_pac_script = expected_pac_script;
    result.action = DROP_RESOLVER;
    return result;
  }

  static CreateProxyResolverAction DropBoth(
      const std::string& expected_pac_script) {
    CreateProxyResolverAction result;
    result.expected_pac_script = expected_pac_script;
    result.action = DROP_BOTH;
    return result;
  }

  static CreateProxyResolverAction WaitForClientDisconnect(
      const std::string& expected_pac_script) {
    CreateProxyResolverAction result;
    result.expected_pac_script = expected_pac_script;
    result.action = WAIT_FOR_CLIENT_DISCONNECT;
    return result;
  }

  static CreateProxyResolverAction MakeDnsRequest(
      const std::string& expected_pac_script) {
    CreateProxyResolverAction result;
    result.expected_pac_script = expected_pac_script;
    result.action = MAKE_DNS_REQUEST;
    return result;
  }

  std::string expected_pac_script;
  Action action = COMPLETE;
  Error error = OK;
};

struct GetProxyForUrlAction {
  enum Action {
    COMPLETE,
    // Drop the request by closing the reply channel.
    DROP,
    // Disconnect the service.
    DISCONNECT,
    // Wait for the client pipe to be disconnected.
    WAIT_FOR_CLIENT_DISCONNECT,
    // Make a DNS request.
    MAKE_DNS_REQUEST,
  };

  GetProxyForUrlAction() {}
  GetProxyForUrlAction(const GetProxyForUrlAction& other) = default;

  static GetProxyForUrlAction ReturnError(const GURL& url, Error error) {
    GetProxyForUrlAction result;
    result.expected_url = url;
    result.error = error;
    return result;
  }

  static GetProxyForUrlAction ReturnServers(const GURL& url,
                                            const ProxyInfo& proxy_info) {
    GetProxyForUrlAction result;
    result.expected_url = url;
    result.proxy_info = proxy_info;
    return result;
  }

  static GetProxyForUrlAction DropRequest(const GURL& url) {
    GetProxyForUrlAction result;
    result.expected_url = url;
    result.action = DROP;
    return result;
  }

  static GetProxyForUrlAction Disconnect(const GURL& url) {
    GetProxyForUrlAction result;
    result.expected_url = url;
    result.action = DISCONNECT;
    return result;
  }

  static GetProxyForUrlAction WaitForClientDisconnect(const GURL& url) {
    GetProxyForUrlAction result;
    result.expected_url = url;
    result.action = WAIT_FOR_CLIENT_DISCONNECT;
    return result;
  }

  static GetProxyForUrlAction MakeDnsRequest(const GURL& url) {
    GetProxyForUrlAction result;
    result.expected_url = url;
    result.action = MAKE_DNS_REQUEST;
    return result;
  }

  Action action = COMPLETE;
  Error error = OK;
  ProxyInfo proxy_info;
  GURL expected_url;
};

class MockMojoProxyResolver : public interfaces::ProxyResolver {
 public:
  MockMojoProxyResolver();
  ~MockMojoProxyResolver() override;

  void AddGetProxyAction(GetProxyForUrlAction action);

  void WaitForNextRequest();

  void ClearBlockedClients();

  void AddConnection(mojo::InterfaceRequest<interfaces::ProxyResolver> req);

 private:
  // Overridden from interfaces::ProxyResolver:
  void GetProxyForUrl(
      const GURL& url,
      interfaces::ProxyResolverRequestClientPtr client) override;

  void WakeWaiter();

  std::string pac_script_data_;

  std::queue<GetProxyForUrlAction> get_proxy_actions_;

  base::Closure quit_closure_;

  std::vector<std::unique_ptr<interfaces::ProxyResolverRequestClientPtr>>
      blocked_clients_;
  mojo::Binding<interfaces::ProxyResolver> binding_;
};

MockMojoProxyResolver::~MockMojoProxyResolver() {
  EXPECT_TRUE(get_proxy_actions_.empty())
      << "Actions remaining: " << get_proxy_actions_.size();
}

MockMojoProxyResolver::MockMojoProxyResolver() : binding_(this) {
}

void MockMojoProxyResolver::AddGetProxyAction(GetProxyForUrlAction action) {
  get_proxy_actions_.push(action);
}

void MockMojoProxyResolver::WaitForNextRequest() {
  base::RunLoop run_loop;
  quit_closure_ = run_loop.QuitClosure();
  run_loop.Run();
}

void MockMojoProxyResolver::WakeWaiter() {
  if (!quit_closure_.is_null())
    quit_closure_.Run();
  quit_closure_.Reset();
}

void MockMojoProxyResolver::ClearBlockedClients() {
  blocked_clients_.clear();
}

void MockMojoProxyResolver::AddConnection(
    mojo::InterfaceRequest<interfaces::ProxyResolver> req) {
  if (binding_.is_bound())
    binding_.Close();
  binding_.Bind(std::move(req));
}

void MockMojoProxyResolver::GetProxyForUrl(
    const GURL& url,
    interfaces::ProxyResolverRequestClientPtr client) {
  ASSERT_FALSE(get_proxy_actions_.empty());
  GetProxyForUrlAction action = get_proxy_actions_.front();
  get_proxy_actions_.pop();

  EXPECT_EQ(action.expected_url, url);
  client->Alert(url.spec());
  client->OnError(12345, url.spec());
  switch (action.action) {
    case GetProxyForUrlAction::COMPLETE: {
      client->ReportResult(action.error, action.proxy_info);
      break;
    }
    case GetProxyForUrlAction::DROP: {
      client.reset();
      break;
    }
    case GetProxyForUrlAction::DISCONNECT: {
      binding_.Close();
      break;
    }
    case GetProxyForUrlAction::WAIT_FOR_CLIENT_DISCONNECT: {
      base::MessageLoop::ScopedNestableTaskAllower nestable_allower(
          base::MessageLoop::current());
      base::RunLoop run_loop;
      client.set_connection_error_handler(run_loop.QuitClosure());
      run_loop.Run();
      ASSERT_TRUE(client.encountered_error());
      break;
    }
    case GetProxyForUrlAction::MAKE_DNS_REQUEST: {
      auto request = base::MakeUnique<HostResolver::RequestInfo>(
          HostPortPair(url.spec(), 12345));
      interfaces::HostResolverRequestClientPtr dns_client;
      mojo::MakeRequest(&dns_client);
      client->ResolveDns(std::move(request), std::move(dns_client));
      blocked_clients_.push_back(
          base::MakeUnique<interfaces::ProxyResolverRequestClientPtr>(
              std::move(client)));
      break;
    }
  }
  WakeWaiter();
}

class Request {
 public:
  Request(ProxyResolver* resolver, const GURL& url);

  int Resolve();
  void Cancel();
  int WaitForResult();

  const ProxyInfo& results() const { return results_; }
  LoadState load_state() { return request_->GetLoadState(); }
  BoundTestNetLog& net_log() { return net_log_; }
  const TestCompletionCallback& callback() const { return callback_; }

 private:
  ProxyResolver* resolver_;
  const GURL url_;
  ProxyInfo results_;
  std::unique_ptr<ProxyResolver::Request> request_;
  int error_;
  TestCompletionCallback callback_;
  BoundTestNetLog net_log_;
};

Request::Request(ProxyResolver* resolver, const GURL& url)
    : resolver_(resolver), url_(url), error_(0) {
}

int Request::Resolve() {
  error_ = resolver_->GetProxyForURL(url_, &results_, callback_.callback(),
                                     &request_, net_log_.bound());
  return error_;
}

void Request::Cancel() {
  request_.reset();
}

int Request::WaitForResult() {
  error_ = callback_.WaitForResult();
  return error_;
}

class MockMojoProxyResolverFactory : public interfaces::ProxyResolverFactory {
 public:
  MockMojoProxyResolverFactory(
      MockMojoProxyResolver* resolver,
      mojo::InterfaceRequest<interfaces::ProxyResolverFactory> req);
  ~MockMojoProxyResolverFactory() override;

  void AddCreateProxyResolverAction(CreateProxyResolverAction action);

  void WaitForNextRequest();

  void ClearBlockedClients();

 private:
  // Overridden from interfaces::ProxyResolver:
  void CreateResolver(
      const std::string& pac_url,
      mojo::InterfaceRequest<interfaces::ProxyResolver> request,
      interfaces::ProxyResolverFactoryRequestClientPtr client) override;

  void WakeWaiter();

  MockMojoProxyResolver* resolver_;
  std::queue<CreateProxyResolverAction> create_resolver_actions_;

  base::Closure quit_closure_;

  std::vector<std::unique_ptr<interfaces::ProxyResolverFactoryRequestClientPtr>>
      blocked_clients_;
  std::vector<
      std::unique_ptr<mojo::InterfaceRequest<interfaces::ProxyResolver>>>
      blocked_resolver_requests_;
  mojo::Binding<interfaces::ProxyResolverFactory> binding_;
};

MockMojoProxyResolverFactory::MockMojoProxyResolverFactory(
    MockMojoProxyResolver* resolver,
    mojo::InterfaceRequest<interfaces::ProxyResolverFactory> req)
    : resolver_(resolver), binding_(this, std::move(req)) {}

MockMojoProxyResolverFactory::~MockMojoProxyResolverFactory() {
  EXPECT_TRUE(create_resolver_actions_.empty())
      << "Actions remaining: " << create_resolver_actions_.size();
}

void MockMojoProxyResolverFactory::AddCreateProxyResolverAction(
    CreateProxyResolverAction action) {
  create_resolver_actions_.push(action);
}

void MockMojoProxyResolverFactory::WaitForNextRequest() {
  base::RunLoop run_loop;
  quit_closure_ = run_loop.QuitClosure();
  run_loop.Run();
}

void MockMojoProxyResolverFactory::WakeWaiter() {
  if (!quit_closure_.is_null())
    quit_closure_.Run();
  quit_closure_.Reset();
}

void MockMojoProxyResolverFactory::ClearBlockedClients() {
  blocked_clients_.clear();
}

void MockMojoProxyResolverFactory::CreateResolver(
    const std::string& pac_script,
    mojo::InterfaceRequest<interfaces::ProxyResolver> request,
    interfaces::ProxyResolverFactoryRequestClientPtr client) {
  ASSERT_FALSE(create_resolver_actions_.empty());
  CreateProxyResolverAction action = create_resolver_actions_.front();
  create_resolver_actions_.pop();

  EXPECT_EQ(action.expected_pac_script, pac_script);
  client->Alert(pac_script);
  client->OnError(12345, pac_script);
  switch (action.action) {
    case CreateProxyResolverAction::COMPLETE: {
      if (action.error == OK)
        resolver_->AddConnection(std::move(request));
      client->ReportResult(action.error);
      break;
    }
    case CreateProxyResolverAction::DROP_CLIENT: {
      // Save |request| so its pipe isn't closed.
      blocked_resolver_requests_.push_back(
          base::MakeUnique<mojo::InterfaceRequest<interfaces::ProxyResolver>>(
              std::move(request)));
      break;
    }
    case CreateProxyResolverAction::DROP_RESOLVER: {
      // Save |client| so its pipe isn't closed.
      blocked_clients_.push_back(
          base::MakeUnique<interfaces::ProxyResolverFactoryRequestClientPtr>(
              std::move(client)));
      break;
    }
    case CreateProxyResolverAction::DROP_BOTH: {
      // Both |request| and |client| will be closed.
      break;
    }
    case CreateProxyResolverAction::WAIT_FOR_CLIENT_DISCONNECT: {
      base::MessageLoop::ScopedNestableTaskAllower nestable_allower(
          base::MessageLoop::current());
      base::RunLoop run_loop;
      client.set_connection_error_handler(run_loop.QuitClosure());
      run_loop.Run();
      ASSERT_TRUE(client.encountered_error());
      break;
    }
    case CreateProxyResolverAction::MAKE_DNS_REQUEST: {
      auto request = base::MakeUnique<HostResolver::RequestInfo>(
          HostPortPair(pac_script, 12345));
      interfaces::HostResolverRequestClientPtr dns_client;
      mojo::MakeRequest(&dns_client);
      client->ResolveDns(std::move(request), std::move(dns_client));
      blocked_clients_.push_back(
          base::MakeUnique<interfaces::ProxyResolverFactoryRequestClientPtr>(
              std::move(client)));
      break;
    }
  }
  WakeWaiter();
}

void DeleteResolverFactoryRequestCallback(
    std::unique_ptr<ProxyResolverFactory::Request>* request,
    const CompletionCallback& callback,
    int result) {
  ASSERT_TRUE(request);
  EXPECT_TRUE(request->get());
  request->reset();
  callback.Run(result);
}

class MockHostResolver : public HostResolver {
 public:
  enum Event {
    DNS_REQUEST,
  };

  // HostResolver overrides.
  int Resolve(const RequestInfo& info,
              RequestPriority priority,
              AddressList* addresses,
              const CompletionCallback& callback,
              std::unique_ptr<Request>* request,
              const NetLogWithSource& source_net_log) override {
    waiter_.NotifyEvent(DNS_REQUEST);
    return ERR_IO_PENDING;
  }

  int ResolveFromCache(const RequestInfo& info,
                       AddressList* addresses,
                       const NetLogWithSource& source_net_log) override {
    return ERR_DNS_CACHE_MISS;
  }

  HostCache* GetHostCache() override { return nullptr; }

  EventWaiter<Event>& waiter() { return waiter_; }

 private:
  EventWaiter<Event> waiter_;
};

void CheckCapturedNetLogEntries(const std::string& expected_string,
                                const TestNetLogEntry::List& entries) {
  ASSERT_EQ(2u, entries.size());
  EXPECT_EQ(NetLogEventType::PAC_JAVASCRIPT_ALERT, entries[0].type);
  std::string message;
  ASSERT_TRUE(entries[0].GetStringValue("message", &message));
  EXPECT_EQ(expected_string, message);
  ASSERT_FALSE(entries[0].params->HasKey("line_number"));
  message.clear();
  EXPECT_EQ(NetLogEventType::PAC_JAVASCRIPT_ERROR, entries[1].type);
  ASSERT_TRUE(entries[1].GetStringValue("message", &message));
  EXPECT_EQ(expected_string, message);
  int line_number = 0;
  ASSERT_TRUE(entries[1].GetIntegerValue("line_number", &line_number));
  EXPECT_EQ(12345, line_number);
}

}  // namespace

class ProxyResolverFactoryMojoTest : public testing::Test,
                                     public MojoProxyResolverFactory {
 public:
  void SetUp() override {
    mock_proxy_resolver_factory_.reset(new MockMojoProxyResolverFactory(
        &mock_proxy_resolver_, mojo::MakeRequest(&factory_ptr_)));
    proxy_resolver_factory_mojo_.reset(new ProxyResolverFactoryMojo(
        this, &host_resolver_,
        base::Callback<std::unique_ptr<ProxyResolverErrorObserver>()>(),
        &net_log_));
  }

  std::unique_ptr<Request> MakeRequest(const GURL& url) {
    return base::MakeUnique<Request>(proxy_resolver_mojo_.get(), url);
  }

  std::unique_ptr<base::ScopedClosureRunner> CreateResolver(
      const std::string& pac_script,
      mojo::InterfaceRequest<interfaces::ProxyResolver> req,
      interfaces::ProxyResolverFactoryRequestClientPtr client) override {
    factory_ptr_->CreateResolver(pac_script, std::move(req), std::move(client));
    return base::MakeUnique<base::ScopedClosureRunner>(
        on_delete_callback_.closure());
  }

  ProxyInfo ProxyServersFromPacString(const std::string& pac_string) {
    ProxyInfo proxy_info;
    proxy_info.UsePacString(pac_string);
    return proxy_info;
  }

  void CreateProxyResolver() {
    mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
        CreateProxyResolverAction::ReturnResult(kScriptData, OK));
    TestCompletionCallback callback;
    scoped_refptr<ProxyResolverScriptData> pac_script(
        ProxyResolverScriptData::FromUTF8(kScriptData));
    std::unique_ptr<ProxyResolverFactory::Request> request;
    ASSERT_EQ(
        OK,
        callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
            pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
    EXPECT_TRUE(request);
    ASSERT_TRUE(proxy_resolver_mojo_);
  }

  void DeleteProxyResolverCallback(const CompletionCallback& callback,
                                   int result) {
    proxy_resolver_mojo_.reset();
    callback.Run(result);
  }

  MockHostResolver host_resolver_;
  TestNetLog net_log_;
  std::unique_ptr<MockMojoProxyResolverFactory> mock_proxy_resolver_factory_;
  interfaces::ProxyResolverFactoryPtr factory_ptr_;
  std::unique_ptr<ProxyResolverFactory> proxy_resolver_factory_mojo_;

  MockMojoProxyResolver mock_proxy_resolver_;
  TestClosure on_delete_callback_;
  std::unique_ptr<ProxyResolver> proxy_resolver_mojo_;
};

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver) {
  CreateProxyResolver();
  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  CheckCapturedNetLogEntries(kScriptData, entries);
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_Empty) {
  TestCompletionCallback callback;
  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(""));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_FAILED,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
  EXPECT_FALSE(request);
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_Url) {
  TestCompletionCallback callback;
  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromURL(GURL(kExampleUrl)));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_FAILED,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
  EXPECT_FALSE(request);
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_Failed) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::ReturnResult(kScriptData,
                                              ERR_PAC_STATUS_NOT_OK));

  TestCompletionCallback callback;
  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  EXPECT_EQ(
      ERR_PAC_STATUS_NOT_OK,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
  EXPECT_TRUE(request);
  on_delete_callback_.WaitForResult();

  // A second attempt succeeds.
  CreateProxyResolver();
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_BothDisconnected) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::DropBoth(kScriptData));

  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_TERMINATED,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
  EXPECT_TRUE(request);
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_ClientDisconnected) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::DropClient(kScriptData));

  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_TERMINATED,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
  EXPECT_TRUE(request);
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_ResolverDisconnected) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::DropResolver(kScriptData));

  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_TERMINATED,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_, callback.callback(), &request)));
  EXPECT_TRUE(request);
  on_delete_callback_.WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest,
       CreateProxyResolver_ResolverDisconnected_DeleteRequestInCallback) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::DropResolver(kScriptData));

  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_TERMINATED,
      callback.GetResult(proxy_resolver_factory_mojo_->CreateProxyResolver(
          pac_script, &proxy_resolver_mojo_,
          base::Bind(&DeleteResolverFactoryRequestCallback, &request,
                     callback.callback()),
          &request)));
  on_delete_callback_.WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_Cancel) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::WaitForClientDisconnect(kScriptData));

  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING, proxy_resolver_factory_mojo_->CreateProxyResolver(
                                pac_script, &proxy_resolver_mojo_,
                                callback.callback(), &request));
  ASSERT_TRUE(request);
  request.reset();

  // The Mojo request is still made.
  mock_proxy_resolver_factory_->WaitForNextRequest();
  on_delete_callback_.WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest, CreateProxyResolver_DnsRequest) {
  mock_proxy_resolver_factory_->AddCreateProxyResolverAction(
      CreateProxyResolverAction::MakeDnsRequest(kScriptData));

  scoped_refptr<ProxyResolverScriptData> pac_script(
      ProxyResolverScriptData::FromUTF8(kScriptData));
  std::unique_ptr<ProxyResolverFactory::Request> request;
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING, proxy_resolver_factory_mojo_->CreateProxyResolver(
                                pac_script, &proxy_resolver_mojo_,
                                callback.callback(), &request));
  ASSERT_TRUE(request);
  host_resolver_.waiter().WaitForEvent(MockHostResolver::DNS_REQUEST);
  mock_proxy_resolver_factory_->ClearBlockedClients();
  callback.WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL) {
  const GURL url(kExampleUrl);
  mock_proxy_resolver_.AddGetProxyAction(GetProxyForUrlAction::ReturnServers(
      url, ProxyServersFromPacString("DIRECT")));
  CreateProxyResolver();
  net_log_.Clear();

  std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request->Resolve(), IsError(ERR_IO_PENDING));
  EXPECT_THAT(request->WaitForResult(), IsOk());

  EXPECT_EQ("DIRECT", request->results().ToPacString());

  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  CheckCapturedNetLogEntries(url.spec(), entries);
  entries.clear();
  request->net_log().GetEntries(&entries);
  CheckCapturedNetLogEntries(url.spec(), entries);
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_MultipleResults) {
  static const char kPacString[] =
      "PROXY foo1:80;DIRECT;SOCKS foo2:1234;"
      "SOCKS5 foo3:1080;HTTPS foo4:443;QUIC foo6:8888";
  mock_proxy_resolver_.AddGetProxyAction(GetProxyForUrlAction::ReturnServers(
      GURL(kExampleUrl), ProxyServersFromPacString(kPacString)));
  CreateProxyResolver();

  std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request->Resolve(), IsError(ERR_IO_PENDING));
  EXPECT_THAT(request->WaitForResult(), IsOk());

  EXPECT_EQ(kPacString, request->results().ToPacString());
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_Error) {
  mock_proxy_resolver_.AddGetProxyAction(
      GetProxyForUrlAction::ReturnError(GURL(kExampleUrl), ERR_UNEXPECTED));
  CreateProxyResolver();

  std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request->Resolve(), IsError(ERR_IO_PENDING));
  EXPECT_THAT(request->WaitForResult(), IsError(ERR_UNEXPECTED));

  EXPECT_TRUE(request->results().is_empty());
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_Cancel) {
  mock_proxy_resolver_.AddGetProxyAction(
      GetProxyForUrlAction::WaitForClientDisconnect(GURL(kExampleUrl)));
  CreateProxyResolver();

  std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request->Resolve(), IsError(ERR_IO_PENDING));
  request->Cancel();
  EXPECT_FALSE(request->callback().have_result());

  // The Mojo request is still made.
  mock_proxy_resolver_.WaitForNextRequest();
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_MultipleRequests) {
  mock_proxy_resolver_.AddGetProxyAction(GetProxyForUrlAction::ReturnServers(
      GURL(kExampleUrl), ProxyServersFromPacString("DIRECT")));
  mock_proxy_resolver_.AddGetProxyAction(GetProxyForUrlAction::ReturnServers(
      GURL("https://www.chromium.org"),
      ProxyServersFromPacString("HTTPS foo:443")));
  CreateProxyResolver();

  std::unique_ptr<Request> request1(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request1->Resolve(), IsError(ERR_IO_PENDING));
  std::unique_ptr<Request> request2(
      MakeRequest(GURL("https://www.chromium.org")));
  EXPECT_THAT(request2->Resolve(), IsError(ERR_IO_PENDING));

  EXPECT_THAT(request1->WaitForResult(), IsOk());
  EXPECT_THAT(request2->WaitForResult(), IsOk());

  EXPECT_EQ("DIRECT", request1->results().ToPacString());
  EXPECT_EQ("HTTPS foo:443", request2->results().ToPacString());
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_Disconnect) {
  mock_proxy_resolver_.AddGetProxyAction(
      GetProxyForUrlAction::Disconnect(GURL(kExampleUrl)));
  CreateProxyResolver();
  {
    std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
    EXPECT_THAT(request->Resolve(), IsError(ERR_IO_PENDING));
    EXPECT_THAT(request->WaitForResult(), IsError(ERR_PAC_SCRIPT_TERMINATED));
    EXPECT_TRUE(request->results().is_empty());
  }

  // Run Watcher::OnHandleReady() tasks posted by Watcher::CallOnHandleReady().
  base::RunLoop().RunUntilIdle();

  {
    // Calling GetProxyForURL after a disconnect should fail.
    std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
    EXPECT_THAT(request->Resolve(), IsError(ERR_PAC_SCRIPT_TERMINATED));
  }
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_ClientClosed) {
  mock_proxy_resolver_.AddGetProxyAction(
      GetProxyForUrlAction::DropRequest(GURL(kExampleUrl)));
  CreateProxyResolver();

  std::unique_ptr<Request> request1(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request1->Resolve(), IsError(ERR_IO_PENDING));

  EXPECT_THAT(request1->WaitForResult(), IsError(ERR_PAC_SCRIPT_TERMINATED));
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_DeleteInCallback) {
  mock_proxy_resolver_.AddGetProxyAction(GetProxyForUrlAction::ReturnServers(
      GURL(kExampleUrl), ProxyServersFromPacString("DIRECT")));
  CreateProxyResolver();

  ProxyInfo results;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolver::Request> request;
  NetLogWithSource net_log;
  EXPECT_EQ(
      OK,
      callback.GetResult(proxy_resolver_mojo_->GetProxyForURL(
          GURL(kExampleUrl), &results,
          base::Bind(&ProxyResolverFactoryMojoTest::DeleteProxyResolverCallback,
                     base::Unretained(this), callback.callback()),
          &request, net_log)));
  on_delete_callback_.WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest,
       GetProxyForURL_DeleteInCallbackFromDisconnect) {
  mock_proxy_resolver_.AddGetProxyAction(
      GetProxyForUrlAction::Disconnect(GURL(kExampleUrl)));
  CreateProxyResolver();

  ProxyInfo results;
  TestCompletionCallback callback;
  std::unique_ptr<ProxyResolver::Request> request;
  NetLogWithSource net_log;
  EXPECT_EQ(
      ERR_PAC_SCRIPT_TERMINATED,
      callback.GetResult(proxy_resolver_mojo_->GetProxyForURL(
          GURL(kExampleUrl), &results,
          base::Bind(&ProxyResolverFactoryMojoTest::DeleteProxyResolverCallback,
                     base::Unretained(this), callback.callback()),
          &request, net_log)));
  on_delete_callback_.WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest, GetProxyForURL_DnsRequest) {
  mock_proxy_resolver_.AddGetProxyAction(
      GetProxyForUrlAction::MakeDnsRequest(GURL(kExampleUrl)));
  CreateProxyResolver();

  std::unique_ptr<Request> request(MakeRequest(GURL(kExampleUrl)));
  EXPECT_THAT(request->Resolve(), IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL, request->load_state());

  host_resolver_.waiter().WaitForEvent(MockHostResolver::DNS_REQUEST);
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST_IN_PROXY_SCRIPT, request->load_state());
  mock_proxy_resolver_.ClearBlockedClients();
  request->WaitForResult();
}

TEST_F(ProxyResolverFactoryMojoTest, DeleteResolver) {
  CreateProxyResolver();
  proxy_resolver_mojo_.reset();
  on_delete_callback_.WaitForResult();
}
}  // namespace net
