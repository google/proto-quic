// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_resolver_impl.h"

#include <string>
#include <utility>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "net/base/net_errors.h"
#include "net/proxy/mock_proxy_resolver.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver_v8_tracing.h"
#include "net/proxy/proxy_server.h"
#include "net/test/event_waiter.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

class TestRequestClient : public interfaces::ProxyResolverRequestClient {
 public:
  enum Event {
    RESULT_RECEIVED,
    CONNECTION_ERROR,
  };

  explicit TestRequestClient(
      mojo::InterfaceRequest<interfaces::ProxyResolverRequestClient> request);

  void WaitForResult();

  Error error() { return error_; }
  const ProxyInfo& results() { return results_; }
  EventWaiter<Event>& event_waiter() { return event_waiter_; }

 private:
  // interfaces::ProxyResolverRequestClient override.
  void ReportResult(int32_t error, const ProxyInfo& results) override;
  void Alert(const std::string& message) override;
  void OnError(int32_t line_number, const std::string& message) override;
  void ResolveDns(std::unique_ptr<HostResolver::RequestInfo> request_info,
                  interfaces::HostResolverRequestClientPtr client) override;

  // Mojo error handler.
  void OnConnectionError();

  bool done_ = false;
  Error error_ = ERR_FAILED;
  ProxyInfo results_;

  mojo::Binding<interfaces::ProxyResolverRequestClient> binding_;

  EventWaiter<Event> event_waiter_;
};

TestRequestClient::TestRequestClient(
    mojo::InterfaceRequest<interfaces::ProxyResolverRequestClient> request)
    : binding_(this, std::move(request)) {
  binding_.set_connection_error_handler(base::Bind(
      &TestRequestClient::OnConnectionError, base::Unretained(this)));
}

void TestRequestClient::WaitForResult() {
  if (done_)
    return;

  event_waiter_.WaitForEvent(RESULT_RECEIVED);
  ASSERT_TRUE(done_);
}

void TestRequestClient::ReportResult(int32_t error, const ProxyInfo& results) {
  event_waiter_.NotifyEvent(RESULT_RECEIVED);
  ASSERT_FALSE(done_);
  error_ = static_cast<Error>(error);
  results_ = results;
  done_ = true;
}

void TestRequestClient::Alert(const std::string& message) {}

void TestRequestClient::OnError(int32_t line_number,
                                const std::string& message) {}

void TestRequestClient::ResolveDns(
    std::unique_ptr<HostResolver::RequestInfo> request_info,
    interfaces::HostResolverRequestClientPtr client) {}

void TestRequestClient::OnConnectionError() {
  event_waiter_.NotifyEvent(CONNECTION_ERROR);
}

class MockProxyResolverV8Tracing : public ProxyResolverV8Tracing {
 public:
  struct Job {
    GURL url;
    ProxyInfo* results;
    bool cancelled = false;
    void Complete(int result) {
      DCHECK(!callback_.is_null());
      callback_.Run(result);
      callback_.Reset();
    }

    bool WasCompleted() { return callback_.is_null(); }

    void SetCallback(CompletionCallback callback) { callback_ = callback; }

   private:
    CompletionCallback callback_;
  };

  class RequestImpl : public ProxyResolver::Request {
   public:
    RequestImpl(Job* job, MockProxyResolverV8Tracing* resolver)
        : job_(job), resolver_(resolver) {}

    ~RequestImpl() override {
      if (job_->WasCompleted())
        return;
      job_->cancelled = true;
      if (!resolver_->cancel_callback_.is_null()) {
        resolver_->cancel_callback_.Run();
        resolver_->cancel_callback_.Reset();
      }
    }

    LoadState GetLoadState() override {
      return LOAD_STATE_RESOLVING_PROXY_FOR_URL;
    }

   private:
    Job* job_;
    MockProxyResolverV8Tracing* resolver_;
  };

  MockProxyResolverV8Tracing() {}

  // ProxyResolverV8Tracing overrides.
  void GetProxyForURL(const GURL& url,
                      ProxyInfo* results,
                      const CompletionCallback& callback,
                      std::unique_ptr<ProxyResolver::Request>* request,
                      std::unique_ptr<Bindings> bindings) override;

  void WaitForCancel();

  const std::vector<std::unique_ptr<Job>>& pending_jobs() {
    return pending_jobs_;
  }

 private:
  base::Closure cancel_callback_;
  std::vector<std::unique_ptr<Job>> pending_jobs_;
};

void MockProxyResolverV8Tracing::GetProxyForURL(
    const GURL& url,
    ProxyInfo* results,
    const CompletionCallback& callback,
    std::unique_ptr<ProxyResolver::Request>* request,
    std::unique_ptr<Bindings> bindings) {
  pending_jobs_.push_back(base::WrapUnique(new Job()));
  auto* pending_job = pending_jobs_.back().get();
  pending_job->url = url;
  pending_job->results = results;
  pending_job->SetCallback(callback);
  request->reset(new RequestImpl(pending_job, this));
}


void MockProxyResolverV8Tracing::WaitForCancel() {
  while (std::find_if(pending_jobs_.begin(), pending_jobs_.end(),
                      [](const std::unique_ptr<Job>& job) {
                        return job->cancelled;
                      }) != pending_jobs_.end()) {
    base::RunLoop run_loop;
    cancel_callback_ = run_loop.QuitClosure();
    run_loop.Run();
  }
}

}  // namespace

class MojoProxyResolverImplTest : public testing::Test {
 protected:
  void SetUp() override {
    std::unique_ptr<MockProxyResolverV8Tracing> mock_resolver(
        new MockProxyResolverV8Tracing);
    mock_proxy_resolver_ = mock_resolver.get();
    resolver_impl_.reset(new MojoProxyResolverImpl(std::move(mock_resolver)));
    resolver_ = resolver_impl_.get();
  }

  MockProxyResolverV8Tracing* mock_proxy_resolver_;

  std::unique_ptr<MojoProxyResolverImpl> resolver_impl_;
  interfaces::ProxyResolver* resolver_;
};

TEST_F(MojoProxyResolverImplTest, GetProxyForUrl) {
  interfaces::ProxyResolverRequestClientPtr client_ptr;
  TestRequestClient client(mojo::MakeRequest(&client_ptr));

  resolver_->GetProxyForUrl(GURL(GURL("http://example.com")),
                            std::move(client_ptr));
  ASSERT_EQ(1u, mock_proxy_resolver_->pending_jobs().size());
  MockProxyResolverV8Tracing::Job* job =
      mock_proxy_resolver_->pending_jobs()[0].get();
  EXPECT_EQ(GURL(GURL("http://example.com")), job->url);

  job->results->UsePacString(
      "PROXY proxy.example.com:1; "
      "SOCKS4 socks4.example.com:2; "
      "SOCKS5 socks5.example.com:3; "
      "HTTPS https.example.com:4; "
      "QUIC quic.example.com:65000; "
      "DIRECT");
  job->Complete(OK);
  client.WaitForResult();

  EXPECT_THAT(client.error(), IsOk());
  std::vector<ProxyServer> servers = client.results().proxy_list().GetAll();
  ASSERT_EQ(6u, servers.size());
  EXPECT_EQ(ProxyServer::SCHEME_HTTP, servers[0].scheme());
  EXPECT_EQ("proxy.example.com", servers[0].host_port_pair().host());
  EXPECT_EQ(1, servers[0].host_port_pair().port());

  EXPECT_EQ(ProxyServer::SCHEME_SOCKS4, servers[1].scheme());
  EXPECT_EQ("socks4.example.com", servers[1].host_port_pair().host());
  EXPECT_EQ(2, servers[1].host_port_pair().port());

  EXPECT_EQ(ProxyServer::SCHEME_SOCKS5, servers[2].scheme());
  EXPECT_EQ("socks5.example.com", servers[2].host_port_pair().host());
  EXPECT_EQ(3, servers[2].host_port_pair().port());

  EXPECT_EQ(ProxyServer::SCHEME_HTTPS, servers[3].scheme());
  EXPECT_EQ("https.example.com", servers[3].host_port_pair().host());
  EXPECT_EQ(4, servers[3].host_port_pair().port());

  EXPECT_EQ(ProxyServer::SCHEME_QUIC, servers[4].scheme());
  EXPECT_EQ("quic.example.com", servers[4].host_port_pair().host());
  EXPECT_EQ(65000, servers[4].host_port_pair().port());

  EXPECT_EQ(ProxyServer::SCHEME_DIRECT, servers[5].scheme());
}

TEST_F(MojoProxyResolverImplTest, GetProxyForUrlFailure) {
  interfaces::ProxyResolverRequestClientPtr client_ptr;
  TestRequestClient client(mojo::MakeRequest(&client_ptr));

  resolver_->GetProxyForUrl(GURL("http://example.com"), std::move(client_ptr));
  ASSERT_EQ(1u, mock_proxy_resolver_->pending_jobs().size());
  MockProxyResolverV8Tracing::Job* job =
      mock_proxy_resolver_->pending_jobs()[0].get();
  EXPECT_EQ(GURL(GURL("http://example.com")), job->url);
  job->Complete(ERR_FAILED);
  client.WaitForResult();

  EXPECT_THAT(client.error(), IsError(ERR_FAILED));
  std::vector<ProxyServer> proxy_servers =
      client.results().proxy_list().GetAll();
  EXPECT_TRUE(proxy_servers.empty());
}

TEST_F(MojoProxyResolverImplTest, GetProxyForUrlMultiple) {
  interfaces::ProxyResolverRequestClientPtr client_ptr1;
  TestRequestClient client1(mojo::MakeRequest(&client_ptr1));
  interfaces::ProxyResolverRequestClientPtr client_ptr2;
  TestRequestClient client2(mojo::MakeRequest(&client_ptr2));

  resolver_->GetProxyForUrl(GURL("http://example.com"), std::move(client_ptr1));
  resolver_->GetProxyForUrl(GURL("https://example.com"),
                            std::move(client_ptr2));
  ASSERT_EQ(2u, mock_proxy_resolver_->pending_jobs().size());
  MockProxyResolverV8Tracing::Job* job1 =
      mock_proxy_resolver_->pending_jobs()[0].get();
  EXPECT_EQ(GURL(GURL("http://example.com")), job1->url);
  MockProxyResolverV8Tracing::Job* job2 =
      mock_proxy_resolver_->pending_jobs()[1].get();
  EXPECT_EQ(GURL("https://example.com"), job2->url);
  job1->results->UsePacString("HTTPS proxy.example.com:12345");
  job1->Complete(OK);
  job2->results->UsePacString("SOCKS5 another-proxy.example.com:6789");
  job2->Complete(OK);
  client1.WaitForResult();
  client2.WaitForResult();

  EXPECT_THAT(client1.error(), IsOk());
  std::vector<ProxyServer> proxy_servers1 =
      client1.results().proxy_list().GetAll();
  ASSERT_EQ(1u, proxy_servers1.size());
  ProxyServer& server1 = proxy_servers1[0];
  EXPECT_EQ(ProxyServer::SCHEME_HTTPS, server1.scheme());
  EXPECT_EQ("proxy.example.com", server1.host_port_pair().host());
  EXPECT_EQ(12345, server1.host_port_pair().port());

  EXPECT_THAT(client2.error(), IsOk());
  std::vector<ProxyServer> proxy_servers2 =
      client2.results().proxy_list().GetAll();
  ASSERT_EQ(1u, proxy_servers1.size());
  ProxyServer& server2 = proxy_servers2[0];
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS5, server2.scheme());
  EXPECT_EQ("another-proxy.example.com", server2.host_port_pair().host());
  EXPECT_EQ(6789, server2.host_port_pair().port());
}

TEST_F(MojoProxyResolverImplTest, DestroyClient) {
  interfaces::ProxyResolverRequestClientPtr client_ptr;
  std::unique_ptr<TestRequestClient> client(
      new TestRequestClient(mojo::MakeRequest(&client_ptr)));

  resolver_->GetProxyForUrl(GURL("http://example.com"), std::move(client_ptr));
  ASSERT_EQ(1u, mock_proxy_resolver_->pending_jobs().size());
  const MockProxyResolverV8Tracing::Job* job =
      mock_proxy_resolver_->pending_jobs()[0].get();
  EXPECT_EQ(GURL(GURL("http://example.com")), job->url);
  job->results->UsePacString("PROXY proxy.example.com:8080");
  client.reset();
  mock_proxy_resolver_->WaitForCancel();
}

TEST_F(MojoProxyResolverImplTest, DestroyService) {
  interfaces::ProxyResolverRequestClientPtr client_ptr;
  TestRequestClient client(mojo::MakeRequest(&client_ptr));

  resolver_->GetProxyForUrl(GURL("http://example.com"), std::move(client_ptr));
  ASSERT_EQ(1u, mock_proxy_resolver_->pending_jobs().size());
  resolver_impl_.reset();
  client.event_waiter().WaitForEvent(TestRequestClient::CONNECTION_ERROR);
}

}  // namespace net
