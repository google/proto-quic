// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_delegate.h"

#include "base/logging.h"
#include "base/profiler/scoped_tracker.h"
#include "base/trace_event/trace_event.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/proxy/proxy_info.h"
#include "net/url_request/url_request.h"

namespace net {

NetworkDelegate::~NetworkDelegate() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

int NetworkDelegate::NotifyBeforeURLRequest(
    URLRequest* request, const CompletionCallback& callback,
    GURL* new_url) {
  TRACE_EVENT0(kNetTracingCategory, "NetworkDelegate::NotifyBeforeURLRequest");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(request);
  DCHECK(!callback.is_null());

  // ClusterFuzz depends on the following VLOG. See: crbug.com/715656
  VLOG(1) << "NetworkDelegate::NotifyBeforeURLRequest: " << request->url();

  // TODO(cbentzel): Remove ScopedTracker below once crbug.com/475753 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "475753 NetworkDelegate::OnBeforeURLRequest"));
  return OnBeforeURLRequest(request, callback, new_url);
}

int NetworkDelegate::NotifyBeforeStartTransaction(
    URLRequest* request,
    const CompletionCallback& callback,
    HttpRequestHeaders* headers) {
  TRACE_EVENT0(kNetTracingCategory,
               "NetworkDelegate::NotifyBeforeStartTransation");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(headers);
  DCHECK(!callback.is_null());
  return OnBeforeStartTransaction(request, callback, headers);
}

void NetworkDelegate::NotifyBeforeSendHeaders(
    URLRequest* request,
    const ProxyInfo& proxy_info,
    const ProxyRetryInfoMap& proxy_retry_info,
    HttpRequestHeaders* headers) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(headers);
  OnBeforeSendHeaders(request, proxy_info, proxy_retry_info, headers);
}

void NetworkDelegate::NotifyStartTransaction(
    URLRequest* request,
    const HttpRequestHeaders& headers) {
  TRACE_EVENT0(kNetTracingCategory, "NetworkDelegate::NotifyStartTransaction");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  OnStartTransaction(request, headers);
}

int NetworkDelegate::NotifyHeadersReceived(
    URLRequest* request,
    const CompletionCallback& callback,
    const HttpResponseHeaders* original_response_headers,
    scoped_refptr<HttpResponseHeaders>* override_response_headers,
    GURL* allowed_unsafe_redirect_url) {
  TRACE_EVENT0(kNetTracingCategory, "NetworkDelegate::NotifyHeadersReceived");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(original_response_headers);
  DCHECK(!callback.is_null());
  return OnHeadersReceived(request,
                           callback,
                           original_response_headers,
                           override_response_headers,
                           allowed_unsafe_redirect_url);
}

void NetworkDelegate::NotifyResponseStarted(URLRequest* request,
                                            int net_error) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(request);

  OnResponseStarted(request, net_error);
}

void NetworkDelegate::NotifyNetworkBytesReceived(URLRequest* request,
                                                 int64_t bytes_received) {
  TRACE_EVENT0(kNetTracingCategory,
               "NetworkDelegate::NotifyNetworkBytesReceived");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_GT(bytes_received, 0);
  OnNetworkBytesReceived(request, bytes_received);
}

void NetworkDelegate::NotifyNetworkBytesSent(URLRequest* request,
                                             int64_t bytes_sent) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_GT(bytes_sent, 0);
  OnNetworkBytesSent(request, bytes_sent);
}

void NetworkDelegate::NotifyBeforeRedirect(URLRequest* request,
                                           const GURL& new_location) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(request);
  OnBeforeRedirect(request, new_location);
}

void NetworkDelegate::NotifyCompleted(URLRequest* request,
                                      bool started,
                                      int net_error) {
  TRACE_EVENT0(kNetTracingCategory, "NetworkDelegate::NotifyCompleted");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(request);
  // TODO(cbentzel): Remove ScopedTracker below once crbug.com/475753 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION("475753 NetworkDelegate::OnCompleted"));

  OnCompleted(request, started, net_error);
}

void NetworkDelegate::NotifyURLRequestDestroyed(URLRequest* request) {
  TRACE_EVENT0(kNetTracingCategory,
               "NetworkDelegate::NotifyURLRequestDestroyed");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(request);
  OnURLRequestDestroyed(request);
}

void NetworkDelegate::NotifyPACScriptError(int line_number,
                                           const base::string16& error) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  OnPACScriptError(line_number, error);
}

NetworkDelegate::AuthRequiredResponse NetworkDelegate::NotifyAuthRequired(
    URLRequest* request,
    const AuthChallengeInfo& auth_info,
    const AuthCallback& callback,
    AuthCredentials* credentials) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnAuthRequired(request, auth_info, callback, credentials);
}

bool NetworkDelegate::CanGetCookies(const URLRequest& request,
                                    const CookieList& cookie_list) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!(request.load_flags() & LOAD_DO_NOT_SEND_COOKIES));
  return OnCanGetCookies(request, cookie_list);
}

bool NetworkDelegate::CanSetCookie(const URLRequest& request,
                                   const std::string& cookie_line,
                                   CookieOptions* options) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!(request.load_flags() & LOAD_DO_NOT_SAVE_COOKIES));
  return OnCanSetCookie(request, cookie_line, options);
}

bool NetworkDelegate::CanAccessFile(const URLRequest& request,
                                    const base::FilePath& original_path,
                                    const base::FilePath& absolute_path) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCanAccessFile(request, original_path, absolute_path);
}

bool NetworkDelegate::CanEnablePrivacyMode(
    const GURL& url,
    const GURL& first_party_for_cookies) const {
  TRACE_EVENT0(kNetTracingCategory, "NetworkDelegate::CanEnablePrivacyMode");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCanEnablePrivacyMode(url, first_party_for_cookies);
}

bool NetworkDelegate::AreExperimentalCookieFeaturesEnabled() const {
  return OnAreExperimentalCookieFeaturesEnabled();
}

bool NetworkDelegate::CancelURLRequestWithPolicyViolatingReferrerHeader(
    const URLRequest& request,
    const GURL& target_url,
    const GURL& referrer_url) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCancelURLRequestWithPolicyViolatingReferrerHeader(
      request, target_url, referrer_url);
}

bool NetworkDelegate::CanQueueReportingReport(const url::Origin& origin) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCanQueueReportingReport(origin);
}

bool NetworkDelegate::CanSendReportingReport(const url::Origin& origin) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCanSendReportingReport(origin);
}

bool NetworkDelegate::CanSetReportingClient(const url::Origin& origin,
                                            const GURL& endpoint) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCanSetReportingClient(origin, endpoint);
}

bool NetworkDelegate::CanUseReportingClient(const url::Origin& origin,
                                            const GURL& endpoint) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return OnCanUseReportingClient(origin, endpoint);
}

void NetworkDelegate::OnResponseStarted(URLRequest* request, int net_error) {
  OnResponseStarted(request);
}

// Deprecated
void NetworkDelegate::OnResponseStarted(URLRequest* request) {
  NOTREACHED();
}

void NetworkDelegate::OnCompleted(URLRequest* request,
                                  bool started,
                                  int net_error) {
  OnCompleted(request, started);
}

// Deprecated.
void NetworkDelegate::OnCompleted(URLRequest* request, bool started) {
  NOTREACHED();
}

}  // namespace net
