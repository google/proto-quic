// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/dhcp_proxy_script_adapter_fetcher_win.h"

#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/test_timeouts.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/timer/elapsed_timer.h"
#include "base/timer/timer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/proxy/mock_proxy_script_fetcher.h"
#include "net/proxy/proxy_script_fetcher_impl.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kPacUrl[] = "http://pacserver/script.pac";

// In net/proxy/dhcp_proxy_script_fetcher_win_unittest.cc there are a few
// tests that exercise DhcpProxyScriptAdapterFetcher end-to-end along with
// DhcpProxyScriptFetcherWin, i.e. it tests the end-to-end usage of Win32
// APIs and the network.  In this file we test only by stubbing out
// functionality.

// Version of DhcpProxyScriptAdapterFetcher that mocks out dependencies
// to allow unit testing.
class MockDhcpProxyScriptAdapterFetcher
    : public DhcpProxyScriptAdapterFetcher {
 public:
  explicit MockDhcpProxyScriptAdapterFetcher(
      URLRequestContext* context,
      scoped_refptr<base::TaskRunner> task_runner)
      : DhcpProxyScriptAdapterFetcher(context, task_runner),
        dhcp_delay_(base::TimeDelta::FromMilliseconds(1)),
        timeout_(TestTimeouts::action_timeout()),
        configured_url_(kPacUrl),
        fetcher_delay_ms_(1),
        fetcher_result_(OK),
        pac_script_("bingo") {
  }

  void Cancel() override {
    DhcpProxyScriptAdapterFetcher::Cancel();
    fetcher_ = NULL;
  }

  ProxyScriptFetcher* ImplCreateScriptFetcher() override {
    // We don't maintain ownership of the fetcher, it is transferred to
    // the caller.
    fetcher_ = new MockProxyScriptFetcher();
    if (fetcher_delay_ms_ != -1) {
      fetcher_timer_.Start(FROM_HERE,
          base::TimeDelta::FromMilliseconds(fetcher_delay_ms_),
          this, &MockDhcpProxyScriptAdapterFetcher::OnFetcherTimer);
    }
    return fetcher_;
  }

  class DelayingDhcpQuery : public DhcpQuery {
   public:
    explicit DelayingDhcpQuery()
        : DhcpQuery(),
          test_finished_event_(
              base::WaitableEvent::ResetPolicy::MANUAL,
              base::WaitableEvent::InitialState::NOT_SIGNALED) {}

    std::string ImplGetPacURLFromDhcp(
        const std::string& adapter_name) override {
      base::ElapsedTimer timer;
      test_finished_event_.TimedWait(dhcp_delay_);
      return configured_url_;
    }

    base::WaitableEvent test_finished_event_;
    base::TimeDelta dhcp_delay_;
    std::string configured_url_;

   private:
    ~DelayingDhcpQuery() override {}
  };

  DhcpQuery* ImplCreateDhcpQuery() override {
    dhcp_query_ = new DelayingDhcpQuery();
    dhcp_query_->dhcp_delay_ = dhcp_delay_;
    dhcp_query_->configured_url_ = configured_url_;
    return dhcp_query_.get();
  }

  // Use a shorter timeout so tests can finish more quickly.
  base::TimeDelta ImplGetTimeout() const override { return timeout_; }

  void OnFetcherTimer() {
    // Note that there is an assumption by this mock implementation that
    // DhcpProxyScriptAdapterFetcher::Fetch will call ImplCreateScriptFetcher
    // and call Fetch on the fetcher before the message loop is re-entered.
    // This holds true today, but if you hit this DCHECK the problem can
    // possibly be resolved by having a separate subclass of
    // MockProxyScriptFetcher that adds the delay internally (instead of
    // the simple approach currently used in ImplCreateScriptFetcher above).
    DCHECK(fetcher_ && fetcher_->has_pending_request());
    fetcher_->NotifyFetchCompletion(fetcher_result_, pac_script_);
    fetcher_ = NULL;
  }

  bool IsWaitingForFetcher() const {
    return state() == STATE_WAIT_URL;
  }

  bool WasCancelled() const {
    return state() == STATE_CANCEL;
  }

  void FinishTest() {
    DCHECK(dhcp_query_.get());
    dhcp_query_->test_finished_event_.Signal();
  }

  base::TimeDelta dhcp_delay_;
  base::TimeDelta timeout_;
  std::string configured_url_;
  int fetcher_delay_ms_;
  int fetcher_result_;
  std::string pac_script_;
  MockProxyScriptFetcher* fetcher_;
  base::OneShotTimer fetcher_timer_;
  scoped_refptr<DelayingDhcpQuery> dhcp_query_;
};

class FetcherClient {
 public:
  FetcherClient()
      : url_request_context_(new TestURLRequestContext()),
        worker_pool_(
            new base::SequencedWorkerPool(4,
                                          "DhcpAdapterFetcherTest",
                                          base::TaskPriority::USER_VISIBLE)),
        fetcher_(new MockDhcpProxyScriptAdapterFetcher(
            url_request_context_.get(),
            worker_pool_->GetTaskRunnerWithShutdownBehavior(
                base::SequencedWorkerPool::CONTINUE_ON_SHUTDOWN))) {}

  ~FetcherClient() {
    worker_pool_->Shutdown();
  }

  void WaitForResult(int expected_error) {
    EXPECT_EQ(expected_error, callback_.WaitForResult());
  }

  void RunTest() {
    fetcher_->Fetch("adapter name", callback_.callback());
  }

  void FinishTestAllowCleanup() {
    fetcher_->FinishTest();
    base::RunLoop().RunUntilIdle();
  }

  TestCompletionCallback callback_;
  std::unique_ptr<URLRequestContext> url_request_context_;
  scoped_refptr<base::SequencedWorkerPool> worker_pool_;
  std::unique_ptr<MockDhcpProxyScriptAdapterFetcher> fetcher_;
  base::string16 pac_text_;
};

TEST(DhcpProxyScriptAdapterFetcher, NormalCaseURLNotInDhcp) {
  FetcherClient client;
  client.fetcher_->configured_url_ = "";
  client.RunTest();
  client.WaitForResult(ERR_PAC_NOT_IN_DHCP);
  ASSERT_TRUE(client.fetcher_->DidFinish());
  EXPECT_THAT(client.fetcher_->GetResult(), IsError(ERR_PAC_NOT_IN_DHCP));
  EXPECT_EQ(base::string16(L""), client.fetcher_->GetPacScript());
}

TEST(DhcpProxyScriptAdapterFetcher, NormalCaseURLInDhcp) {
  FetcherClient client;
  client.RunTest();
  client.WaitForResult(OK);
  ASSERT_TRUE(client.fetcher_->DidFinish());
  EXPECT_THAT(client.fetcher_->GetResult(), IsOk());
  EXPECT_EQ(base::string16(L"bingo"), client.fetcher_->GetPacScript());
  EXPECT_EQ(GURL(kPacUrl), client.fetcher_->GetPacURL());
}

TEST(DhcpProxyScriptAdapterFetcher, TimeoutDuringDhcp) {
  // Does a Fetch() with a long enough delay on accessing DHCP that the
  // fetcher should time out.  This is to test a case manual testing found,
  // where under certain circumstances (e.g. adapter enabled for DHCP and
  // needs to retrieve its configuration from DHCP, but no DHCP server
  // present on the network) accessing DHCP can take on the order of tens
  // of seconds.
  FetcherClient client;
  client.fetcher_->dhcp_delay_ = TestTimeouts::action_max_timeout();
  client.fetcher_->timeout_ = base::TimeDelta::FromMilliseconds(25);

  base::ElapsedTimer timer;
  client.RunTest();
  // An error different from this would be received if the timeout didn't
  // kick in.
  client.WaitForResult(ERR_TIMED_OUT);

  ASSERT_TRUE(client.fetcher_->DidFinish());
  EXPECT_THAT(client.fetcher_->GetResult(), IsError(ERR_TIMED_OUT));
  EXPECT_EQ(base::string16(L""), client.fetcher_->GetPacScript());
  EXPECT_EQ(GURL(), client.fetcher_->GetPacURL());
  client.FinishTestAllowCleanup();
}

TEST(DhcpProxyScriptAdapterFetcher, CancelWhileDhcp) {
  FetcherClient client;
  client.RunTest();
  client.fetcher_->Cancel();
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(client.fetcher_->DidFinish());
  ASSERT_TRUE(client.fetcher_->WasCancelled());
  EXPECT_THAT(client.fetcher_->GetResult(), IsError(ERR_ABORTED));
  EXPECT_EQ(base::string16(L""), client.fetcher_->GetPacScript());
  EXPECT_EQ(GURL(), client.fetcher_->GetPacURL());
  client.FinishTestAllowCleanup();
}

TEST(DhcpProxyScriptAdapterFetcher, CancelWhileFetcher) {
  FetcherClient client;
  // This causes the mock fetcher not to pretend the
  // fetcher finishes after a timeout.
  client.fetcher_->fetcher_delay_ms_ = -1;
  client.RunTest();
  int max_loops = 4;
  while (!client.fetcher_->IsWaitingForFetcher() && max_loops--) {
    base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(10));
    base::RunLoop().RunUntilIdle();
  }
  client.fetcher_->Cancel();
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(client.fetcher_->DidFinish());
  ASSERT_TRUE(client.fetcher_->WasCancelled());
  EXPECT_THAT(client.fetcher_->GetResult(), IsError(ERR_ABORTED));
  EXPECT_EQ(base::string16(L""), client.fetcher_->GetPacScript());
  // GetPacURL() still returns the URL fetched in this case.
  EXPECT_EQ(GURL(kPacUrl), client.fetcher_->GetPacURL());
  client.FinishTestAllowCleanup();
}

TEST(DhcpProxyScriptAdapterFetcher, CancelAtCompletion) {
  FetcherClient client;
  client.RunTest();
  client.WaitForResult(OK);
  client.fetcher_->Cancel();
  // Canceling after you're done should have no effect, so these
  // are identical expectations to the NormalCaseURLInDhcp test.
  ASSERT_TRUE(client.fetcher_->DidFinish());
  EXPECT_THAT(client.fetcher_->GetResult(), IsOk());
  EXPECT_EQ(base::string16(L"bingo"), client.fetcher_->GetPacScript());
  EXPECT_EQ(GURL(kPacUrl), client.fetcher_->GetPacURL());
  client.FinishTestAllowCleanup();
}

// Does a real fetch on a mock DHCP configuration.
class MockDhcpRealFetchProxyScriptAdapterFetcher
    : public MockDhcpProxyScriptAdapterFetcher {
 public:
  explicit MockDhcpRealFetchProxyScriptAdapterFetcher(
      URLRequestContext* context,
      scoped_refptr<base::TaskRunner> task_runner)
      : MockDhcpProxyScriptAdapterFetcher(context, task_runner),
        url_request_context_(context) {
  }

  // Returns a real proxy script fetcher.
  ProxyScriptFetcher* ImplCreateScriptFetcher() override {
    ProxyScriptFetcher* fetcher =
        new ProxyScriptFetcherImpl(url_request_context_);
    return fetcher;
  }

  URLRequestContext* url_request_context_;
};

TEST(DhcpProxyScriptAdapterFetcher, MockDhcpRealFetch) {
  EmbeddedTestServer test_server;
  test_server.ServeFilesFromSourceDirectory(
      "net/data/proxy_script_fetcher_unittest");
  ASSERT_TRUE(test_server.Start());

  GURL configured_url = test_server.GetURL("/downloadable.pac");

  FetcherClient client;
  TestURLRequestContext url_request_context;
  scoped_refptr<base::TaskRunner> runner =
      client.worker_pool_->GetTaskRunnerWithShutdownBehavior(
          base::SequencedWorkerPool::CONTINUE_ON_SHUTDOWN);
  client.fetcher_.reset(
      new MockDhcpRealFetchProxyScriptAdapterFetcher(
          &url_request_context, runner));
  client.fetcher_->configured_url_ = configured_url.spec();
  client.RunTest();
  client.WaitForResult(OK);
  ASSERT_TRUE(client.fetcher_->DidFinish());
  EXPECT_THAT(client.fetcher_->GetResult(), IsOk());
  EXPECT_EQ(base::string16(L"-downloadable.pac-\n"),
            client.fetcher_->GetPacScript());
  EXPECT_EQ(configured_url,
            client.fetcher_->GetPacURL());
}

#define BASE_URL "http://corpserver/proxy.pac"

TEST(DhcpProxyScriptAdapterFetcher, SanitizeDhcpApiString) {
  const size_t kBaseUrlLen = strlen(BASE_URL);

  // Default case.
  EXPECT_EQ(BASE_URL,
            DhcpProxyScriptAdapterFetcher::SanitizeDhcpApiString(
                BASE_URL, kBaseUrlLen));

  // Trailing \n and no null-termination.
  EXPECT_EQ(BASE_URL,
            DhcpProxyScriptAdapterFetcher::SanitizeDhcpApiString(
                BASE_URL "\nblablabla", kBaseUrlLen + 1));

  // Embedded NULLs.
  EXPECT_EQ(BASE_URL,
            DhcpProxyScriptAdapterFetcher::SanitizeDhcpApiString(
                BASE_URL "\0foo\0blat", kBaseUrlLen + 9));
}

#undef BASE_URL

}  // namespace

}  // namespace net
