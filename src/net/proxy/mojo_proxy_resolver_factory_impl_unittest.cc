// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_resolver_factory_impl.h"

#include <utility>

#include "base/memory/ptr_util.h"
#include "base/strings/utf_string_conversions.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/base/test_completion_callback.h"
#include "net/proxy/mock_proxy_resolver.h"
#include "net/proxy/proxy_resolver_v8_tracing.h"
#include "net/test/event_waiter.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

const char kScriptData[] = "FooBarBaz";

class FakeProxyResolver : public ProxyResolverV8Tracing {
 public:
  explicit FakeProxyResolver(const base::Closure& on_destruction)
      : on_destruction_(on_destruction) {}

  ~FakeProxyResolver() override { on_destruction_.Run(); }

 private:
  // ProxyResolverV8Tracing overrides.
  void GetProxyForURL(const GURL& url,
                      ProxyInfo* results,
                      const CompletionCallback& callback,
                      std::unique_ptr<ProxyResolver::Request>* request,
                      std::unique_ptr<Bindings> bindings) override {}

  const base::Closure on_destruction_;
};

enum Event {
  NONE,
  RESOLVER_CREATED,
  CONNECTION_ERROR,
  RESOLVER_DESTROYED,
};

class TestProxyResolverFactory : public ProxyResolverV8TracingFactory {
 public:
  struct PendingRequest {
    std::unique_ptr<ProxyResolverV8Tracing>* resolver;
    CompletionCallback callback;
  };

  explicit TestProxyResolverFactory(EventWaiter<Event>* waiter)
      : waiter_(waiter) {}

  void CreateProxyResolverV8Tracing(
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      std::unique_ptr<ProxyResolverV8Tracing::Bindings> bindings,
      std::unique_ptr<ProxyResolverV8Tracing>* resolver,
      const CompletionCallback& callback,
      std::unique_ptr<ProxyResolverFactory::Request>* request) override {
    requests_handled_++;
    waiter_->NotifyEvent(RESOLVER_CREATED);
    EXPECT_EQ(base::ASCIIToUTF16(kScriptData), pac_script->utf16());
    EXPECT_TRUE(resolver);
    pending_request_.reset(new PendingRequest);
    pending_request_->resolver = resolver;
    pending_request_->callback = callback;

    ASSERT_TRUE(bindings);

    bindings->Alert(base::ASCIIToUTF16("alert"));
    bindings->OnError(10, base::ASCIIToUTF16("error"));
    EXPECT_TRUE(bindings->GetHostResolver());
  }

  size_t requests_handled() { return requests_handled_; }
  const PendingRequest* pending_request() { return pending_request_.get(); }

 private:
  EventWaiter<Event>* waiter_;
  size_t requests_handled_ = 0;
  std::unique_ptr<PendingRequest> pending_request_;
};

}  // namespace

class MojoProxyResolverFactoryImplTest
    : public testing::Test,
      public interfaces::ProxyResolverFactoryRequestClient {
 public:
  void SetUp() override {
    mock_factory_ = new TestProxyResolverFactory(&waiter_);
    mojo::MakeStrongBinding(base::MakeUnique<MojoProxyResolverFactoryImpl>(
                                base::WrapUnique(mock_factory_)),
                            mojo::MakeRequest(&factory_));
  }

  void OnConnectionError() { waiter_.NotifyEvent(CONNECTION_ERROR); }

  void OnFakeProxyInstanceDestroyed() {
    instances_destroyed_++;
    waiter_.NotifyEvent(RESOLVER_DESTROYED);
  }

  void ReportResult(int32_t error) override { create_callback_.Run(error); }

  void Alert(const std::string& message) override {}

  void OnError(int32_t line_number, const std::string& message) override {}

  void ResolveDns(std::unique_ptr<HostResolver::RequestInfo> request_info,
                  interfaces::HostResolverRequestClientPtr client) override {}

 protected:
  std::unique_ptr<TestProxyResolverFactory> mock_factory_owner_;
  TestProxyResolverFactory* mock_factory_;
  interfaces::ProxyResolverFactoryPtr factory_;

  int instances_destroyed_ = 0;
  CompletionCallback create_callback_;

  EventWaiter<Event> waiter_;
};

TEST_F(MojoProxyResolverFactoryImplTest, DisconnectProxyResolverClient) {
  interfaces::ProxyResolverPtr proxy_resolver;
  interfaces::ProxyResolverFactoryRequestClientPtr client_ptr;
  mojo::Binding<ProxyResolverFactoryRequestClient> client_binding(
      this, mojo::MakeRequest(&client_ptr));
  factory_->CreateResolver(kScriptData, mojo::MakeRequest(&proxy_resolver),
                           std::move(client_ptr));
  proxy_resolver.set_connection_error_handler(
      base::Bind(&MojoProxyResolverFactoryImplTest::OnConnectionError,
                 base::Unretained(this)));
  waiter_.WaitForEvent(RESOLVER_CREATED);
  EXPECT_EQ(0, instances_destroyed_);
  ASSERT_EQ(1u, mock_factory_->requests_handled());
  TestCompletionCallback create_callback;
  create_callback_ = create_callback.callback();
  ASSERT_TRUE(mock_factory_->pending_request());
  mock_factory_->pending_request()->resolver->reset(
      new FakeProxyResolver(base::Bind(
          &MojoProxyResolverFactoryImplTest::OnFakeProxyInstanceDestroyed,
          base::Unretained(this))));
  mock_factory_->pending_request()->callback.Run(OK);
  EXPECT_THAT(create_callback.WaitForResult(), IsOk());
  proxy_resolver.reset();
  waiter_.WaitForEvent(RESOLVER_DESTROYED);
  EXPECT_EQ(1, instances_destroyed_);
}

TEST_F(MojoProxyResolverFactoryImplTest, Error) {
  interfaces::ProxyResolverPtr proxy_resolver;
  interfaces::ProxyResolverFactoryRequestClientPtr client_ptr;
  mojo::Binding<ProxyResolverFactoryRequestClient> client_binding(
      this, mojo::MakeRequest(&client_ptr));
  factory_->CreateResolver(kScriptData, mojo::MakeRequest(&proxy_resolver),
                           std::move(client_ptr));
  proxy_resolver.set_connection_error_handler(
      base::Bind(&MojoProxyResolverFactoryImplTest::OnConnectionError,
                 base::Unretained(this)));
  waiter_.WaitForEvent(RESOLVER_CREATED);
  EXPECT_EQ(0, instances_destroyed_);
  ASSERT_EQ(1u, mock_factory_->requests_handled());
  TestCompletionCallback create_callback;
  create_callback_ = create_callback.callback();
  ASSERT_TRUE(mock_factory_->pending_request());
  mock_factory_->pending_request()->callback.Run(ERR_PAC_SCRIPT_FAILED);
  EXPECT_THAT(create_callback.WaitForResult(), IsError(ERR_PAC_SCRIPT_FAILED));
}

TEST_F(MojoProxyResolverFactoryImplTest,
       DisconnectClientDuringResolverCreation) {
  interfaces::ProxyResolverPtr proxy_resolver;
  interfaces::ProxyResolverFactoryRequestClientPtr client_ptr;
  mojo::Binding<ProxyResolverFactoryRequestClient> client_binding(
      this, mojo::MakeRequest(&client_ptr));
  factory_->CreateResolver(kScriptData, mojo::MakeRequest(&proxy_resolver),
                           std::move(client_ptr));
  proxy_resolver.set_connection_error_handler(
      base::Bind(&MojoProxyResolverFactoryImplTest::OnConnectionError,
                 base::Unretained(this)));
  waiter_.WaitForEvent(RESOLVER_CREATED);
  EXPECT_EQ(0, instances_destroyed_);
  ASSERT_EQ(1u, mock_factory_->requests_handled());
  client_binding.Close();
  waiter_.WaitForEvent(CONNECTION_ERROR);
}

TEST_F(MojoProxyResolverFactoryImplTest,
       DisconnectFactoryDuringResolverCreation) {
  interfaces::ProxyResolverPtr proxy_resolver;
  interfaces::ProxyResolverFactoryRequestClientPtr client_ptr;
  mojo::Binding<ProxyResolverFactoryRequestClient> client_binding(
      this, mojo::MakeRequest(&client_ptr));
  factory_->CreateResolver(kScriptData, mojo::MakeRequest(&proxy_resolver),
                           std::move(client_ptr));
  proxy_resolver.set_connection_error_handler(
      base::Bind(&MojoProxyResolverFactoryImplTest::OnConnectionError,
                 base::Unretained(this)));
  client_binding.set_connection_error_handler(
      base::Bind(&MojoProxyResolverFactoryImplTest::OnConnectionError,
                 base::Unretained(this)));
  waiter_.WaitForEvent(RESOLVER_CREATED);
  EXPECT_EQ(0, instances_destroyed_);
  ASSERT_EQ(1u, mock_factory_->requests_handled());
  factory_.reset();
  waiter_.WaitForEvent(CONNECTION_ERROR);
}

}  // namespace net
