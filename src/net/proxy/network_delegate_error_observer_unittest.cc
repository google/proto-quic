// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/network_delegate_error_observer.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate_impl.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class TestNetworkDelegate : public NetworkDelegateImpl {
 public:
  TestNetworkDelegate() : got_pac_error_(false) {}
  ~TestNetworkDelegate() override {}

  bool got_pac_error() const { return got_pac_error_; }

 private:
  // NetworkDelegate implementation.
  int OnBeforeURLRequest(URLRequest* request,
                         const CompletionCallback& callback,
                         GURL* new_url) override {
    return OK;
  }
  int OnBeforeStartTransaction(URLRequest* request,
                               const CompletionCallback& callback,
                               HttpRequestHeaders* headers) override {
    return OK;
  }
  void OnStartTransaction(URLRequest* request,
                          const HttpRequestHeaders& headers) override {}
  int OnHeadersReceived(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) override {
    return OK;
  }
  void OnBeforeRedirect(URLRequest* request,
                        const GURL& new_location) override {}
  void OnResponseStarted(URLRequest* request, int net_error) override {}
  void OnCompleted(URLRequest* request, bool started, int net_error) override {}
  void OnURLRequestDestroyed(URLRequest* request) override {}

  void OnPACScriptError(int line_number, const base::string16& error) override {
    got_pac_error_ = true;
  }
  AuthRequiredResponse OnAuthRequired(URLRequest* request,
                                      const AuthChallengeInfo& auth_info,
                                      const AuthCallback& callback,
                                      AuthCredentials* credentials) override {
    return AUTH_REQUIRED_RESPONSE_NO_ACTION;
  }
  bool OnCanGetCookies(const URLRequest& request,
                       const CookieList& cookie_list) override {
    return true;
  }
  bool OnCanSetCookie(const URLRequest& request,
                      const std::string& cookie_line,
                      CookieOptions* options) override {
    return true;
  }
  bool OnCanAccessFile(const URLRequest& request,
                       const base::FilePath& path) const override {
    return true;
  }

  bool got_pac_error_;
};

// Check that the OnPACScriptError method can be called from an arbitrary
// thread.
TEST(NetworkDelegateErrorObserverTest, CallOnThread) {
  base::Thread thread("test_thread");
  thread.Start();
  TestNetworkDelegate network_delegate;
  NetworkDelegateErrorObserver observer(
      &network_delegate, base::ThreadTaskRunnerHandle::Get().get());
  thread.task_runner()->PostTask(
      FROM_HERE, base::Bind(&NetworkDelegateErrorObserver::OnPACScriptError,
                            base::Unretained(&observer), 42, base::string16()));
  thread.Stop();
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(network_delegate.got_pac_error());
}

// Check that passing a NULL network delegate works.
TEST(NetworkDelegateErrorObserverTest, NoDelegate) {
  base::Thread thread("test_thread");
  thread.Start();
  NetworkDelegateErrorObserver observer(
      NULL, base::ThreadTaskRunnerHandle::Get().get());
  thread.task_runner()->PostTask(
      FROM_HERE, base::Bind(&NetworkDelegateErrorObserver::OnPACScriptError,
                            base::Unretained(&observer), 42, base::string16()));
  thread.Stop();
  base::RunLoop().RunUntilIdle();
  // Shouldn't have crashed until here...
}

}  // namespace

}  // namespace net
