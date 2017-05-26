// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_LAYERED_NETWORK_DELEGATE_H_
#define NET_BASE_LAYERED_NETWORK_DELEGATE_H_

#include <stdint.h>

#include <memory>

#include "base/strings/string16.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/base/network_delegate.h"
#include "net/cookies/canonical_cookie.h"
#include "net/proxy/proxy_retry_info.h"

class GURL;

namespace base {
class FilePath;
}

namespace net {

class CookieOptions;
class HttpRequestHeaders;
class HttpResponseHeaders;
class ProxyInfo;
class URLRequest;

// LayeredNetworkDelegate takes a |network_delegate| and extends it. When
// On*() is called, the On*Internal() method of this is first called and then
// the On*() of |network_delegate| is called. On*Internal() methods have no
// return values, and cannot prevent calling into the nested network delegate.
class NET_EXPORT LayeredNetworkDelegate : public NetworkDelegate {
 public:
  explicit LayeredNetworkDelegate(
      std::unique_ptr<NetworkDelegate> nested_network_delegate);
  ~LayeredNetworkDelegate() override;

  // NetworkDelegate implementation:
  int OnBeforeURLRequest(URLRequest* request,
                         const CompletionCallback& callback,
                         GURL* new_url) final;
  int OnBeforeStartTransaction(URLRequest* request,
                               const CompletionCallback& callback,
                               HttpRequestHeaders* headers) final;
  void OnBeforeSendHeaders(URLRequest* request,
                           const ProxyInfo& proxy_info,
                           const ProxyRetryInfoMap& proxy_retry_info,
                           HttpRequestHeaders* headers) final;
  void OnStartTransaction(URLRequest* request,
                          const HttpRequestHeaders& headers) final;
  int OnHeadersReceived(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) final;
  void OnBeforeRedirect(URLRequest* request, const GURL& new_location) final;

  void OnResponseStarted(URLRequest* request, int net_error) final;
  void OnNetworkBytesReceived(URLRequest* request,
                              int64_t bytes_received) final;
  void OnNetworkBytesSent(URLRequest* request, int64_t bytes_sent) final;
  void OnCompleted(URLRequest* request, bool started, int net_error) final;
  void OnURLRequestDestroyed(URLRequest* request) final;
  void OnPACScriptError(int line_number, const base::string16& error) final;
  AuthRequiredResponse OnAuthRequired(URLRequest* request,
                                      const AuthChallengeInfo& auth_info,
                                      const AuthCallback& callback,
                                      AuthCredentials* credentials) final;
  bool OnCanGetCookies(const URLRequest& request,
                       const CookieList& cookie_list) final;
  bool OnCanSetCookie(const URLRequest& request,
                      const std::string& cookie_line,
                      CookieOptions* options) final;
  bool OnCanAccessFile(const URLRequest& request,
                       const base::FilePath& path) const final;
  bool OnCanEnablePrivacyMode(const GURL& url,
                              const GURL& first_party_for_cookies) const final;
  bool OnAreExperimentalCookieFeaturesEnabled() const final;
  bool OnCancelURLRequestWithPolicyViolatingReferrerHeader(
      const URLRequest& request,
      const GURL& target_url,
      const GURL& referrer_url) const final;

  bool OnCanQueueReportingReport(const url::Origin& origin) const final;

  bool OnCanSendReportingReport(const url::Origin& origin) const final;

  bool OnCanSetReportingClient(const url::Origin& origin,
                               const GURL& endpoint) const final;

  bool OnCanUseReportingClient(const url::Origin& origin,
                               const GURL& endpoint) const final;

 protected:
  virtual void OnBeforeURLRequestInternal(URLRequest* request,
                                          const CompletionCallback& callback,
                                          GURL* new_url);

  virtual void OnBeforeStartTransactionInternal(
      URLRequest* request,
      const CompletionCallback& callback,
      HttpRequestHeaders* headers);

  virtual void OnBeforeSendHeadersInternal(
      URLRequest* request,
      const ProxyInfo& proxy_info,
      const ProxyRetryInfoMap& proxy_retry_info,
      HttpRequestHeaders* headers);

  virtual void OnStartTransactionInternal(URLRequest* request,
                                          const HttpRequestHeaders& headers);

  virtual void OnHeadersReceivedInternal(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url);

  virtual void OnBeforeRedirectInternal(URLRequest* request,
                                        const GURL& new_location);

  virtual void OnResponseStartedInternal(URLRequest* request);

  virtual void OnNetworkBytesReceivedInternal(URLRequest* request,
                                              int64_t bytes_received);

  virtual void OnNetworkBytesSentInternal(URLRequest* request,
                                          int64_t bytes_sent);

  virtual void OnCompletedInternal(URLRequest* request, bool started);

  virtual void OnURLRequestDestroyedInternal(URLRequest* request);

  virtual void OnPACScriptErrorInternal(int line_number,
                                        const base::string16& error);

  virtual void OnCanGetCookiesInternal(const URLRequest& request,
                                       const CookieList& cookie_list);

  virtual void OnCanSetCookieInternal(const URLRequest& request,
                                      const std::string& cookie_line,
                                      CookieOptions* options);

  virtual void OnAuthRequiredInternal(URLRequest* request,
                                      const AuthChallengeInfo& auth_info,
                                      const AuthCallback& callback,
                                      AuthCredentials* credentials);

  virtual void OnCanAccessFileInternal(const URLRequest& request,
                                       const base::FilePath& path) const;

  virtual void OnCanEnablePrivacyModeInternal(
      const GURL& url,
      const GURL& first_party_for_cookies) const;

  virtual void OnAreExperimentalCookieFeaturesEnabledInternal() const;

  virtual void OnCancelURLRequestWithPolicyViolatingReferrerHeaderInternal(
      const URLRequest& request,
      const GURL& target_url,
      const GURL& referrer_url) const;

  virtual void OnCanQueueReportingReportInternal(
      const url::Origin& origin) const;

  virtual void OnCanSendReportingReportInternal(
      const url::Origin& origin) const;

  virtual void OnCanSetReportingClientInternal(const url::Origin& origin,
                                               const GURL& endpoint) const;

  virtual void OnCanUseReportingClientInternal(const url::Origin& origin,
                                               const GURL& endpoint) const;

 private:
  std::unique_ptr<NetworkDelegate> nested_network_delegate_;
};

}  // namespace net

#endif  // NET_BASE_LAYERED_NETWORK_DELEGATE_H_
