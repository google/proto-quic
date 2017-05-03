// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "base/bind.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/dhcp_proxy_script_fetcher.h"
#include "net/proxy/mock_proxy_script_fetcher.h"
#include "net/proxy/proxy_config.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_script_decider.h"
#include "net/proxy/proxy_script_fetcher.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_request_context.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

enum Error {
  kFailedDownloading = -100,
  kFailedParsing = ERR_PAC_SCRIPT_FAILED,
};

class Rules {
 public:
  struct Rule {
    Rule(const GURL& url, int fetch_error, bool is_valid_script)
        : url(url),
          fetch_error(fetch_error),
          is_valid_script(is_valid_script) {
    }

    base::string16 text() const {
      if (is_valid_script)
        return base::UTF8ToUTF16(url.spec() + "!FindProxyForURL");
      if (fetch_error == OK)
        return base::UTF8ToUTF16(url.spec() + "!invalid-script");
      return base::string16();
    }

    GURL url;
    int fetch_error;
    bool is_valid_script;
  };

  Rule AddSuccessRule(const char* url) {
    Rule rule(GURL(url), OK /*fetch_error*/, true);
    rules_.push_back(rule);
    return rule;
  }

  void AddFailDownloadRule(const char* url) {
    rules_.push_back(Rule(GURL(url), kFailedDownloading /*fetch_error*/,
        false));
  }

  void AddFailParsingRule(const char* url) {
    rules_.push_back(Rule(GURL(url), OK /*fetch_error*/, false));
  }

  const Rule& GetRuleByUrl(const GURL& url) const {
    for (RuleList::const_iterator it = rules_.begin(); it != rules_.end();
         ++it) {
      if (it->url == url)
        return *it;
    }
    LOG(FATAL) << "Rule not found for " << url;
    return rules_[0];
  }

  const Rule& GetRuleByText(const base::string16& text) const {
    for (RuleList::const_iterator it = rules_.begin(); it != rules_.end();
         ++it) {
      if (it->text() == text)
        return *it;
    }
    LOG(FATAL) << "Rule not found for " << text;
    return rules_[0];
  }

 private:
  typedef std::vector<Rule> RuleList;
  RuleList rules_;
};

class RuleBasedProxyScriptFetcher : public ProxyScriptFetcher {
 public:
  explicit RuleBasedProxyScriptFetcher(const Rules* rules)
      : rules_(rules), request_context_(NULL) {}

  virtual void SetRequestContext(URLRequestContext* context) {
    request_context_ = context;
  }

  // ProxyScriptFetcher implementation.
  int Fetch(const GURL& url,
            base::string16* text,
            const CompletionCallback& callback) override {
    const Rules::Rule& rule = rules_->GetRuleByUrl(url);
    int rv = rule.fetch_error;
    EXPECT_NE(ERR_UNEXPECTED, rv);
    if (rv == OK)
      *text = rule.text();
    return rv;
  }

  void Cancel() override {}

  void OnShutdown() override { request_context_ = nullptr; }

  URLRequestContext* GetRequestContext() const override {
    return request_context_;
  }

 private:
  const Rules* rules_;
  URLRequestContext* request_context_;
};

// A mock retriever, returns asynchronously when CompleteRequests() is called.
class MockDhcpProxyScriptFetcher : public DhcpProxyScriptFetcher {
 public:
  MockDhcpProxyScriptFetcher();
  ~MockDhcpProxyScriptFetcher() override;

  int Fetch(base::string16* utf16_text,
            const CompletionCallback& callback) override;
  void Cancel() override;
  void OnShutdown() override;
  const GURL& GetPacURL() const override;

  virtual void SetPacURL(const GURL& url);

  virtual void CompleteRequests(int result, const base::string16& script);

 private:
  CompletionCallback callback_;
  base::string16* utf16_text_;
  GURL gurl_;
  DISALLOW_COPY_AND_ASSIGN(MockDhcpProxyScriptFetcher);
};

MockDhcpProxyScriptFetcher::MockDhcpProxyScriptFetcher() { }

MockDhcpProxyScriptFetcher::~MockDhcpProxyScriptFetcher() { }

int MockDhcpProxyScriptFetcher::Fetch(base::string16* utf16_text,
                                      const CompletionCallback& callback) {
  utf16_text_ = utf16_text;
  callback_ = callback;
  return ERR_IO_PENDING;
}

void MockDhcpProxyScriptFetcher::Cancel() { }

void MockDhcpProxyScriptFetcher::OnShutdown() {}

const GURL& MockDhcpProxyScriptFetcher::GetPacURL() const {
  return gurl_;
}

void MockDhcpProxyScriptFetcher::SetPacURL(const GURL& url) {
  gurl_ = url;
}

void MockDhcpProxyScriptFetcher::CompleteRequests(
    int result, const base::string16& script) {
  *utf16_text_ = script;
  callback_.Run(result);
}

// Succeed using custom PAC script.
TEST(ProxyScriptDeciderTest, CustomPacSucceeds) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  Rules::Rule rule = rules.AddSuccessRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  TestNetLog log;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, &log);
  EXPECT_EQ(OK, decider.Start(
      config, base::TimeDelta(), true, callback.callback()));
  EXPECT_EQ(rule.text(), decider.script_data()->utf16());

  // Check the NetLog was filled correctly.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SCRIPT_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::PROXY_SCRIPT_DECIDER));

  EXPECT_TRUE(decider.effective_config().has_pac_url());
  EXPECT_EQ(config.pac_url(), decider.effective_config().pac_url());
}

// Fail downloading the custom PAC script.
TEST(ProxyScriptDeciderTest, CustomPacFails1) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  TestNetLog log;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, &log);
  EXPECT_EQ(kFailedDownloading,
            decider.Start(config, base::TimeDelta(), true,
                          callback.callback()));
  EXPECT_FALSE(decider.script_data());

  // Check the NetLog was filled correctly.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SCRIPT_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::PROXY_SCRIPT_DECIDER));

  EXPECT_FALSE(decider.effective_config().has_pac_url());
}

// Fail parsing the custom PAC script.
TEST(ProxyScriptDeciderTest, CustomPacFails2) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailParsingRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  EXPECT_EQ(kFailedParsing,
            decider.Start(config, base::TimeDelta(), true,
                          callback.callback()));
  EXPECT_FALSE(decider.script_data());
}

// Fail downloading the custom PAC script, because the fetcher was NULL.
TEST(ProxyScriptDeciderTest, HasNullProxyScriptFetcher) {
  Rules rules;
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  TestCompletionCallback callback;
  ProxyScriptDecider decider(NULL, &dhcp_fetcher, NULL);
  EXPECT_EQ(ERR_UNEXPECTED,
            decider.Start(config, base::TimeDelta(), true,
                          callback.callback()));
  EXPECT_FALSE(decider.script_data());
}

// Succeeds in choosing autodetect (WPAD DNS).
TEST(ProxyScriptDeciderTest, AutodetectSuccess) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);

  Rules::Rule rule = rules.AddSuccessRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  EXPECT_EQ(OK, decider.Start(
      config, base::TimeDelta(), true, callback.callback()));
  EXPECT_EQ(rule.text(), decider.script_data()->utf16());

  EXPECT_TRUE(decider.effective_config().has_pac_url());
  EXPECT_EQ(rule.url, decider.effective_config().pac_url());
}

class ProxyScriptDeciderQuickCheckTest : public ::testing::Test {
 public:
  ProxyScriptDeciderQuickCheckTest()
      : rule_(rules_.AddSuccessRule("http://wpad/wpad.dat")),
        fetcher_(&rules_) { }

  void SetUp() override {
    request_context_.set_host_resolver(&resolver_);
    fetcher_.SetRequestContext(&request_context_);
    config_.set_auto_detect(true);
    decider_.reset(new ProxyScriptDecider(&fetcher_, &dhcp_fetcher_, NULL));
  }

  int StartDecider() {
    return decider_->Start(config_, base::TimeDelta(), true,
                            callback_.callback());
  }

 protected:
  MockHostResolver resolver_;
  Rules rules_;
  Rules::Rule rule_;
  TestCompletionCallback callback_;
  RuleBasedProxyScriptFetcher fetcher_;
  ProxyConfig config_;
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher_;
  std::unique_ptr<ProxyScriptDecider> decider_;

 private:
  URLRequestContext request_context_;
};

// Fails if a synchronous DNS lookup success for wpad causes QuickCheck to fail.
TEST_F(ProxyScriptDeciderQuickCheckTest, SyncSuccess) {
  resolver_.set_synchronous_mode(true);
  resolver_.rules()->AddRule("wpad", "1.2.3.4");

  EXPECT_THAT(StartDecider(), IsOk());
  EXPECT_EQ(rule_.text(), decider_->script_data()->utf16());

  EXPECT_TRUE(decider_->effective_config().has_pac_url());
  EXPECT_EQ(rule_.url, decider_->effective_config().pac_url());
}

// Fails if an asynchronous DNS lookup success for wpad causes QuickCheck to
// fail.
TEST_F(ProxyScriptDeciderQuickCheckTest, AsyncSuccess) {
  resolver_.set_ondemand_mode(true);
  resolver_.rules()->AddRule("wpad", "1.2.3.4");

  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(resolver_.has_pending_requests());
  resolver_.ResolveAllPending();
  callback_.WaitForResult();
  EXPECT_FALSE(resolver_.has_pending_requests());
  EXPECT_EQ(rule_.text(), decider_->script_data()->utf16());
  EXPECT_TRUE(decider_->effective_config().has_pac_url());
  EXPECT_EQ(rule_.url, decider_->effective_config().pac_url());
}

// Fails if an asynchronous DNS lookup failure (i.e. an NXDOMAIN) still causes
// ProxyScriptDecider to yield a PAC URL.
TEST_F(ProxyScriptDeciderQuickCheckTest, AsyncFail) {
  resolver_.set_ondemand_mode(true);
  resolver_.rules()->AddSimulatedFailure("wpad");
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(resolver_.has_pending_requests());
  resolver_.ResolveAllPending();
  callback_.WaitForResult();
  EXPECT_FALSE(decider_->effective_config().has_pac_url());
}

// Fails if a DNS lookup timeout either causes ProxyScriptDecider to yield a PAC
// URL or causes ProxyScriptDecider not to cancel its pending resolution.
TEST_F(ProxyScriptDeciderQuickCheckTest, AsyncTimeout) {
  resolver_.set_ondemand_mode(true);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  ASSERT_TRUE(resolver_.has_pending_requests());
  callback_.WaitForResult();
  EXPECT_FALSE(resolver_.has_pending_requests());
  EXPECT_FALSE(decider_->effective_config().has_pac_url());
}

// Fails if DHCP check doesn't take place before QuickCheck.
TEST_F(ProxyScriptDeciderQuickCheckTest, QuickCheckInhibitsDhcp) {
  MockDhcpProxyScriptFetcher dhcp_fetcher;
  const char *kPac = "function FindProxyForURL(u,h) { return \"DIRECT\"; }";
  base::string16 pac_contents = base::UTF8ToUTF16(kPac);
  GURL url("http://foobar/baz");
  dhcp_fetcher.SetPacURL(url);
  decider_.reset(new ProxyScriptDecider(&fetcher_, &dhcp_fetcher, NULL));
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  dhcp_fetcher.CompleteRequests(OK, pac_contents);
  EXPECT_TRUE(decider_->effective_config().has_pac_url());
  EXPECT_EQ(decider_->effective_config().pac_url(), url);
}

// Fails if QuickCheck still happens when disabled. To ensure QuickCheck is not
// happening, we add a synchronous failing resolver, which would ordinarily
// mean a QuickCheck failure, then ensure that our ProxyScriptFetcher is still
// asked to fetch.
TEST_F(ProxyScriptDeciderQuickCheckTest, QuickCheckDisabled) {
  const char *kPac = "function FindProxyForURL(u,h) { return \"DIRECT\"; }";
  resolver_.set_synchronous_mode(true);
  resolver_.rules()->AddSimulatedFailure("wpad");
  MockProxyScriptFetcher fetcher;
  decider_.reset(new ProxyScriptDecider(&fetcher, &dhcp_fetcher_, NULL));
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(fetcher.has_pending_request());
  fetcher.NotifyFetchCompletion(OK, kPac);
}

TEST_F(ProxyScriptDeciderQuickCheckTest, ExplicitPacUrl) {
  const char *kCustomUrl = "http://custom/proxy.pac";
  config_.set_pac_url(GURL(kCustomUrl));
  Rules::Rule rule = rules_.AddSuccessRule(kCustomUrl);
  resolver_.rules()->AddSimulatedFailure("wpad");
  resolver_.rules()->AddRule("custom", "1.2.3.4");
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  callback_.WaitForResult();
  EXPECT_TRUE(decider_->effective_config().has_pac_url());
  EXPECT_EQ(rule.url, decider_->effective_config().pac_url());
}

TEST_F(ProxyScriptDeciderQuickCheckTest, ShutdownDuringResolve) {
  resolver_.set_ondemand_mode(true);

  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(resolver_.has_pending_requests());

  decider_->OnShutdown();
  EXPECT_FALSE(resolver_.has_pending_requests());
  EXPECT_EQ(ERR_CONTEXT_SHUT_DOWN, callback_.WaitForResult());
}

// Regression test for http://crbug.com/409698.
// This test lets the state machine get into state QUICK_CHECK_COMPLETE, then
// destroys the decider, causing a cancel.
TEST_F(ProxyScriptDeciderQuickCheckTest, CancelPartway) {
  resolver_.set_synchronous_mode(false);
  resolver_.set_ondemand_mode(true);
  EXPECT_THAT(StartDecider(), IsError(ERR_IO_PENDING));
  decider_.reset(NULL);
}

// Fails at WPAD (downloading), but succeeds in choosing the custom PAC.
TEST(ProxyScriptDeciderTest, AutodetectFailCustomSuccess1) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://wpad/wpad.dat");
  Rules::Rule rule = rules.AddSuccessRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  EXPECT_EQ(OK, decider.Start(
      config, base::TimeDelta(), true, callback.callback()));
  EXPECT_EQ(rule.text(), decider.script_data()->utf16());

  EXPECT_TRUE(decider.effective_config().has_pac_url());
  EXPECT_EQ(rule.url, decider.effective_config().pac_url());
}

// Fails at WPAD (no DHCP config, DNS PAC fails parsing), but succeeds in
// choosing the custom PAC.
TEST(ProxyScriptDeciderTest, AutodetectFailCustomSuccess2) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));
  config.proxy_rules().ParseFromString("unused-manual-proxy:99");

  rules.AddFailParsingRule("http://wpad/wpad.dat");
  Rules::Rule rule = rules.AddSuccessRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  TestNetLog log;

  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, &log);
  EXPECT_EQ(OK, decider.Start(config, base::TimeDelta(),
                          true, callback.callback()));
  EXPECT_EQ(rule.text(), decider.script_data()->utf16());

  // Verify that the effective configuration no longer contains auto detect or
  // any of the manual settings.
  EXPECT_TRUE(decider.effective_config().Equals(
      ProxyConfig::CreateFromCustomPacURL(GURL("http://custom/proxy.pac"))));

  // Check the NetLog was filled correctly.
  // (Note that various states are repeated since both WPAD and custom
  // PAC scripts are tried).
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(10u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SCRIPT_DECIDER));
  // This is the DHCP phase, which fails fetching rather than parsing, so
  // there is no pair of SET_PAC_SCRIPT events.
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEvent(
      entries, 3,
      NetLogEventType::PROXY_SCRIPT_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE,
      NetLogEventPhase::NONE));
  // This is the DNS phase, which attempts a fetch but fails.
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 4, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 5, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEvent(
      entries, 6,
      NetLogEventType::PROXY_SCRIPT_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE,
      NetLogEventPhase::NONE));
  // Finally, the custom PAC URL phase.
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 7, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 8, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 9, NetLogEventType::PROXY_SCRIPT_DECIDER));
}

// Fails at WPAD (downloading), and fails at custom PAC (downloading).
TEST(ProxyScriptDeciderTest, AutodetectFailCustomFails1) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://wpad/wpad.dat");
  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  EXPECT_EQ(kFailedDownloading,
            decider.Start(config, base::TimeDelta(), true,
                          callback.callback()));
  EXPECT_FALSE(decider.script_data());
}

// Fails at WPAD (downloading), and fails at custom PAC (parsing).
TEST(ProxyScriptDeciderTest, AutodetectFailCustomFails2) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_auto_detect(true);
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://wpad/wpad.dat");
  rules.AddFailParsingRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  EXPECT_EQ(kFailedParsing,
            decider.Start(config, base::TimeDelta(), true,
                          callback.callback()));
  EXPECT_FALSE(decider.script_data());
}

// This is a copy-paste of CustomPacFails1, with the exception that we give it
// a 1 millisecond delay. This means it will now complete asynchronously.
// Moreover, we test the NetLog to make sure it logged the pause.
TEST(ProxyScriptDeciderTest, CustomPacFails1_WithPositiveDelay) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  TestNetLog log;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, &log);
  EXPECT_EQ(ERR_IO_PENDING,
            decider.Start(config, base::TimeDelta::FromMilliseconds(1),
                      true, callback.callback()));

  EXPECT_EQ(kFailedDownloading, callback.WaitForResult());
  EXPECT_FALSE(decider.script_data());

  // Check the NetLog was filled correctly.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(6u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SCRIPT_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PROXY_SCRIPT_DECIDER_WAIT));
  EXPECT_TRUE(LogContainsEndEvent(entries, 2,
                                  NetLogEventType::PROXY_SCRIPT_DECIDER_WAIT));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 3, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 4, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 5, NetLogEventType::PROXY_SCRIPT_DECIDER));
}

// This is a copy-paste of CustomPacFails1, with the exception that we give it
// a -5 second delay instead of a 0 ms delay. This change should have no effect
// so the rest of the test is unchanged.
TEST(ProxyScriptDeciderTest, CustomPacFails1_WithNegativeDelay) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  DoNothingDhcpProxyScriptFetcher dhcp_fetcher;

  ProxyConfig config;
  config.set_pac_url(GURL("http://custom/proxy.pac"));

  rules.AddFailDownloadRule("http://custom/proxy.pac");

  TestCompletionCallback callback;
  TestNetLog log;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, &log);
  EXPECT_EQ(kFailedDownloading,
            decider.Start(config, base::TimeDelta::FromSeconds(-5),
                          true, callback.callback()));
  EXPECT_FALSE(decider.script_data());

  // Check the NetLog was filled correctly.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 0, NetLogEventType::PROXY_SCRIPT_DECIDER));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 1, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 2, NetLogEventType::PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::PROXY_SCRIPT_DECIDER));
}

class SynchronousSuccessDhcpFetcher : public DhcpProxyScriptFetcher {
 public:
  explicit SynchronousSuccessDhcpFetcher(const base::string16& expected_text)
      : gurl_("http://dhcppac/"), expected_text_(expected_text) {
  }

  int Fetch(base::string16* utf16_text,
            const CompletionCallback& callback) override {
    *utf16_text = expected_text_;
    return OK;
  }

  void Cancel() override {}

  void OnShutdown() override {}

  const GURL& GetPacURL() const override { return gurl_; }

  const base::string16& expected_text() const {
    return expected_text_;
  }

 private:
  GURL gurl_;
  base::string16 expected_text_;

  DISALLOW_COPY_AND_ASSIGN(SynchronousSuccessDhcpFetcher);
};

// All of the tests above that use ProxyScriptDecider have tested
// failure to fetch a PAC file via DHCP configuration, so we now test
// success at downloading and parsing, and then success at downloading,
// failure at parsing.

TEST(ProxyScriptDeciderTest, AutodetectDhcpSuccess) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  SynchronousSuccessDhcpFetcher dhcp_fetcher(
      base::WideToUTF16(L"http://bingo/!FindProxyForURL"));

  ProxyConfig config;
  config.set_auto_detect(true);

  rules.AddSuccessRule("http://bingo/");
  rules.AddFailDownloadRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  EXPECT_EQ(OK, decider.Start(
      config, base::TimeDelta(), true, callback.callback()));
  EXPECT_EQ(dhcp_fetcher.expected_text(),
            decider.script_data()->utf16());

  EXPECT_TRUE(decider.effective_config().has_pac_url());
  EXPECT_EQ(GURL("http://dhcppac/"), decider.effective_config().pac_url());
}

TEST(ProxyScriptDeciderTest, AutodetectDhcpFailParse) {
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);
  SynchronousSuccessDhcpFetcher dhcp_fetcher(
      base::WideToUTF16(L"http://bingo/!invalid-script"));

  ProxyConfig config;
  config.set_auto_detect(true);

  rules.AddFailParsingRule("http://bingo/");
  rules.AddFailDownloadRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;
  ProxyScriptDecider decider(&fetcher, &dhcp_fetcher, NULL);
  // Since there is fallback to DNS-based WPAD, the final error will be that
  // it failed downloading, not that it failed parsing.
  EXPECT_EQ(kFailedDownloading,
      decider.Start(config, base::TimeDelta(), true, callback.callback()));
  EXPECT_FALSE(decider.script_data());

  EXPECT_FALSE(decider.effective_config().has_pac_url());
}

class AsyncFailDhcpFetcher
    : public DhcpProxyScriptFetcher,
      public base::SupportsWeakPtr<AsyncFailDhcpFetcher> {
 public:
  AsyncFailDhcpFetcher() {}
  ~AsyncFailDhcpFetcher() override {}

  int Fetch(base::string16* utf16_text,
            const CompletionCallback& callback) override {
    callback_ = callback;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&AsyncFailDhcpFetcher::CallbackWithFailure, AsWeakPtr()));
    return ERR_IO_PENDING;
  }

  void Cancel() override { callback_.Reset(); }

  void OnShutdown() override {}

  const GURL& GetPacURL() const override { return dummy_gurl_; }

  void CallbackWithFailure() {
    if (!callback_.is_null())
      callback_.Run(ERR_PAC_NOT_IN_DHCP);
  }

 private:
  GURL dummy_gurl_;
  CompletionCallback callback_;
};

TEST(ProxyScriptDeciderTest, DhcpCancelledByDestructor) {
  // This regression test would crash before
  // http://codereview.chromium.org/7044058/
  // Thus, we don't care much about actual results (hence no EXPECT or ASSERT
  // macros below), just that it doesn't crash.
  Rules rules;
  RuleBasedProxyScriptFetcher fetcher(&rules);

  std::unique_ptr<AsyncFailDhcpFetcher> dhcp_fetcher(
      new AsyncFailDhcpFetcher());

  ProxyConfig config;
  config.set_auto_detect(true);
  rules.AddFailDownloadRule("http://wpad/wpad.dat");

  TestCompletionCallback callback;

  // Scope so ProxyScriptDecider gets destroyed early.
  {
    ProxyScriptDecider decider(&fetcher, dhcp_fetcher.get(), NULL);
    decider.Start(config, base::TimeDelta(), true, callback.callback());
  }

  // Run the message loop to let the DHCP fetch complete and post the results
  // back. Before the fix linked to above, this would try to invoke on
  // the callback object provided by ProxyScriptDecider after it was
  // no longer valid.
  base::RunLoop().RunUntilIdle();
}

}  // namespace
}  // namespace net
