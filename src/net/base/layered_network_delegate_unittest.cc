// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/layered_network_delegate.h"

#include <map>
#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/auth.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate_impl.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_response_headers.h"
#include "net/proxy/proxy_config_service.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_retry_info.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {
namespace {

typedef std::map<const char*, int> CountersMap;

class TestNetworkDelegateImpl : public NetworkDelegateImpl {
 public:
  TestNetworkDelegateImpl(CountersMap* layered_network_delegate_counters)
      : layered_network_delegate_counters_(layered_network_delegate_counters) {}

  ~TestNetworkDelegateImpl() override {}

  // NetworkDelegateImpl implementation:
  int OnBeforeURLRequest(URLRequest* request,
                         const CompletionCallback& callback,
                         GURL* new_url) override {
    IncrementAndCompareCounter("on_before_url_request_count");
    return OK;
  }

  int OnBeforeStartTransaction(URLRequest* request,
                               const CompletionCallback& callback,
                               HttpRequestHeaders* headers) override {
    IncrementAndCompareCounter("on_before_start_transaction_count");
    return OK;
  }

  void OnBeforeSendHeaders(URLRequest* request,
                           const ProxyInfo& proxy_info,
                           const ProxyRetryInfoMap& proxy_retry_info,
                           HttpRequestHeaders* headers) override {
    IncrementAndCompareCounter("on_before_send_headers_count");
  }

  void OnStartTransaction(URLRequest* request,
                          const HttpRequestHeaders& headers) override {
    IncrementAndCompareCounter("on_start_transaction_count");
  }

  int OnHeadersReceived(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) override {
    IncrementAndCompareCounter("on_headers_received_count");
    return OK;
  }

  void OnBeforeRedirect(URLRequest* request,
                        const GURL& new_location) override {
    IncrementAndCompareCounter("on_before_redirect_count");
  }

  void OnResponseStarted(URLRequest* request, int net_error) override {
    IncrementAndCompareCounter("on_response_started_count");
  }

  void OnNetworkBytesReceived(URLRequest* request,
                              int64_t bytes_received) override {
    IncrementAndCompareCounter("on_network_bytes_received_count");
  }

  void OnNetworkBytesSent(URLRequest* request, int64_t bytes_sent) override {
    IncrementAndCompareCounter("on_network_bytes_sent_count");
  }

  void OnCompleted(URLRequest* request, bool started, int net_error) override {
    IncrementAndCompareCounter("on_completed_count");
  }

  void OnURLRequestDestroyed(URLRequest* request) override {
    IncrementAndCompareCounter("on_url_request_destroyed_count");
  }

  void OnPACScriptError(int line_number, const base::string16& error) override {
    IncrementAndCompareCounter("on_pac_script_error_count");
  }

  AuthRequiredResponse OnAuthRequired(URLRequest* request,
                                      const AuthChallengeInfo& auth_info,
                                      const AuthCallback& callback,
                                      AuthCredentials* credentials) override {
    IncrementAndCompareCounter("on_auth_required_count");
    return NetworkDelegate::AUTH_REQUIRED_RESPONSE_NO_ACTION;
  }

  bool OnCanGetCookies(const URLRequest& request,
                       const CookieList& cookie_list) override {
    IncrementAndCompareCounter("on_can_get_cookies_count");
    return false;
  }

  bool OnCanSetCookie(const URLRequest& request,
                      const std::string& cookie_line,
                      CookieOptions* options) override {
    IncrementAndCompareCounter("on_can_set_cookie_count");
    return false;
  }

  bool OnCanAccessFile(const URLRequest& request,
                       const base::FilePath& path) const override {
    IncrementAndCompareCounter("on_can_access_file_count");
    return false;
  }

  bool OnCanEnablePrivacyMode(
      const GURL& url,
      const GURL& first_party_for_cookies) const override {
    IncrementAndCompareCounter("on_can_enable_privacy_mode_count");
    return false;
  }

  bool OnCancelURLRequestWithPolicyViolatingReferrerHeader(
      const URLRequest& request,
      const GURL& target_url,
      const GURL& referrer_url) const override {
    IncrementAndCompareCounter(
        "on_cancel_url_request_with_policy_violating_referrer_header_count");
    return false;
  }

 private:
  void IncrementAndCompareCounter(const char* counter_name) const {
    ++counters_[counter_name];
    EXPECT_EQ((*layered_network_delegate_counters_)[counter_name],
              counters_[counter_name]);
  }

  mutable CountersMap counters_;
  mutable CountersMap* layered_network_delegate_counters_;

  DISALLOW_COPY_AND_ASSIGN(TestNetworkDelegateImpl);
};

class TestLayeredNetworkDelegate : public LayeredNetworkDelegate {
 public:
  TestLayeredNetworkDelegate(std::unique_ptr<NetworkDelegate> network_delegate,
                             CountersMap* counters)
      : LayeredNetworkDelegate(std::move(network_delegate)),
        context_(true),
        counters_(counters) {
    context_.Init();
  }

  ~TestLayeredNetworkDelegate() override {}

  void CallAndVerify() {
    scoped_refptr<AuthChallengeInfo> auth_challenge(new AuthChallengeInfo());
    std::unique_ptr<URLRequest> request =
        context_.CreateRequest(GURL(), IDLE, &delegate_);
    std::unique_ptr<HttpRequestHeaders> request_headers(
        new HttpRequestHeaders());
    scoped_refptr<HttpResponseHeaders> response_headers(
        new HttpResponseHeaders(""));
    TestCompletionCallback completion_callback;
    ProxyRetryInfoMap proxy_retry_info;

    EXPECT_EQ(OK, OnBeforeURLRequest(request.get(),
                                     completion_callback.callback(), NULL));
    EXPECT_EQ(OK, OnBeforeStartTransaction(NULL, completion_callback.callback(),
                                           request_headers.get()));
    OnBeforeSendHeaders(NULL, ProxyInfo(), proxy_retry_info,
                        request_headers.get());
    OnStartTransaction(NULL, *request_headers);
    OnNetworkBytesSent(request.get(), 42);
    EXPECT_EQ(OK, OnHeadersReceived(NULL, completion_callback.callback(),
                                    response_headers.get(), NULL, NULL));
    OnResponseStarted(request.get(), net::OK);
    OnNetworkBytesReceived(request.get(), 42);
    OnCompleted(request.get(), false, net::OK);
    OnURLRequestDestroyed(request.get());
    OnPACScriptError(0, base::string16());
    EXPECT_EQ(
        NetworkDelegate::AUTH_REQUIRED_RESPONSE_NO_ACTION,
        OnAuthRequired(request.get(), *auth_challenge, AuthCallback(), NULL));
    EXPECT_FALSE(OnCanGetCookies(*request, CookieList()));
    EXPECT_FALSE(OnCanSetCookie(*request, std::string(), NULL));
    EXPECT_FALSE(OnCanAccessFile(*request, base::FilePath()));
    EXPECT_FALSE(OnCanEnablePrivacyMode(GURL(), GURL()));
    EXPECT_FALSE(OnCancelURLRequestWithPolicyViolatingReferrerHeader(
        *request, GURL(), GURL()));
  }

 protected:
  void OnBeforeURLRequestInternal(URLRequest* request,
                                  const CompletionCallback& callback,
                                  GURL* new_url) override {
    ++(*counters_)["on_before_url_request_count"];
    EXPECT_EQ(1, (*counters_)["on_before_url_request_count"]);
  }

  void OnBeforeStartTransactionInternal(URLRequest* request,
                                        const CompletionCallback& callback,
                                        HttpRequestHeaders* headers) override {
    ++(*counters_)["on_before_start_transaction_count"];
    EXPECT_EQ(1, (*counters_)["on_before_start_transaction_count"]);
  }

  void OnBeforeSendHeadersInternal(URLRequest* request,
                                   const ProxyInfo& proxy_info,
                                   const ProxyRetryInfoMap& proxy_retry_info,
                                   HttpRequestHeaders* headers) override {
    ++(*counters_)["on_before_send_headers_count"];
    EXPECT_EQ(1, (*counters_)["on_before_send_headers_count"]);
  }

  void OnStartTransactionInternal(URLRequest* request,
                                  const HttpRequestHeaders& headers) override {
    ++(*counters_)["on_start_transaction_count"];
    EXPECT_EQ(1, (*counters_)["on_start_transaction_count"]);
  }

  void OnHeadersReceivedInternal(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) override {
    ++(*counters_)["on_headers_received_count"];
    EXPECT_EQ(1, (*counters_)["on_headers_received_count"]);
  }

  void OnBeforeRedirectInternal(URLRequest* request,
                                const GURL& new_location) override {
    ++(*counters_)["on_before_redirect_count"];
    EXPECT_EQ(1, (*counters_)["on_before_redirect_count"]);
  }

  void OnResponseStartedInternal(URLRequest* request) override {
    ++(*counters_)["on_response_started_count"];
    EXPECT_EQ(1, (*counters_)["on_response_started_count"]);
  }

  void OnNetworkBytesReceivedInternal(URLRequest* request,
                                      int64_t bytes_received) override {
    ++(*counters_)["on_network_bytes_received_count"];
    EXPECT_EQ(1, (*counters_)["on_network_bytes_received_count"]);
  }

  void OnNetworkBytesSentInternal(URLRequest* request,
                                  int64_t bytes_sent) override {
    ++(*counters_)["on_network_bytes_sent_count"];
    EXPECT_EQ(1, (*counters_)["on_network_bytes_sent_count"]);
  }

  void OnCompletedInternal(URLRequest* request, bool started) override {
    ++(*counters_)["on_completed_count"];
    EXPECT_EQ(1, (*counters_)["on_completed_count"]);
  }

  void OnURLRequestDestroyedInternal(URLRequest* request) override {
    ++(*counters_)["on_url_request_destroyed_count"];
    EXPECT_EQ(1, (*counters_)["on_url_request_destroyed_count"]);
  }

  void OnPACScriptErrorInternal(int line_number,
                                const base::string16& error) override {
    ++(*counters_)["on_pac_script_error_count"];
    EXPECT_EQ(1, (*counters_)["on_pac_script_error_count"]);
  }

  void OnAuthRequiredInternal(URLRequest* request,
                              const AuthChallengeInfo& auth_info,
                              const AuthCallback& callback,
                              AuthCredentials* credentials) override {
    ++(*counters_)["on_auth_required_count"];
    EXPECT_EQ(1, (*counters_)["on_auth_required_count"]);
  }

  void OnCanGetCookiesInternal(const URLRequest& request,
                               const CookieList& cookie_list) override {
    ++(*counters_)["on_can_get_cookies_count"];
    EXPECT_EQ(1, (*counters_)["on_can_get_cookies_count"]);
  }

  void OnCanSetCookieInternal(const URLRequest& request,
                              const std::string& cookie_line,
                              CookieOptions* options) override {
    ++(*counters_)["on_can_set_cookie_count"];
    EXPECT_EQ(1, (*counters_)["on_can_set_cookie_count"]);
  }

  void OnCanAccessFileInternal(const URLRequest& request,
                               const base::FilePath& path) const override {
    ++(*counters_)["on_can_access_file_count"];
    EXPECT_EQ(1, (*counters_)["on_can_access_file_count"]);
  }

  void OnCanEnablePrivacyModeInternal(
      const GURL& url,
      const GURL& first_party_for_cookies) const override {
    ++(*counters_)["on_can_enable_privacy_mode_count"];
    EXPECT_EQ(1, (*counters_)["on_can_enable_privacy_mode_count"]);
  }

  void OnCancelURLRequestWithPolicyViolatingReferrerHeaderInternal(
      const URLRequest& request,
      const GURL& target_url,
      const GURL& referrer_url) const override {
    ++(*counters_)
        ["on_cancel_url_request_with_policy_"
         "violating_referrer_header_count"];
    EXPECT_EQ(1, (*counters_)
                     ["on_cancel_url_request_with_policy_"
                      "violating_referrer_header_count"]);
  }

 private:
  TestURLRequestContext context_;
  TestDelegate delegate_;
  mutable CountersMap* counters_;

  DISALLOW_COPY_AND_ASSIGN(TestLayeredNetworkDelegate);
};

}  // namespace

class LayeredNetworkDelegateTest : public testing::Test {
 public:
  LayeredNetworkDelegateTest() {
    std::unique_ptr<TestNetworkDelegateImpl> test_network_delegate(
        new TestNetworkDelegateImpl(&layered_network_delegate_counters));
    test_network_delegate_ = test_network_delegate.get();
    layered_network_delegate_ = std::unique_ptr<TestLayeredNetworkDelegate>(
        new TestLayeredNetworkDelegate(std::move(test_network_delegate),
                                       &layered_network_delegate_counters));
  }

  CountersMap layered_network_delegate_counters;
  TestNetworkDelegateImpl* test_network_delegate_;
  std::unique_ptr<TestLayeredNetworkDelegate> layered_network_delegate_;
};

TEST_F(LayeredNetworkDelegateTest, VerifyLayeredNetworkDelegateInternal) {
  layered_network_delegate_->CallAndVerify();
}

}  // namespace net
