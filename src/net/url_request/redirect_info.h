// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_REDIRECT_INFO_H_
#define NET_URL_REQUEST_REDIRECT_INFO_H_

#include <string>

#include "net/base/net_export.h"
#include "net/url_request/url_request.h"
#include "url/gurl.h"

namespace net {

// RedirectInfo captures information about a redirect and any fields in a
// request that change. This struct must be kept in sync with
// content/common/resource_messages.h.
struct NET_EXPORT RedirectInfo {
  RedirectInfo();
  RedirectInfo(const RedirectInfo& other);
  ~RedirectInfo();

  // The status code for the redirect response. This is almost redundant with
  // the response headers, but some URLRequestJobs emit redirects without
  // headers.
  int status_code;

  // The new request method. Depending on the response code, the request method
  // may change.
  std::string new_method;

  // The new request URL.
  GURL new_url;

  // The new first-party URL for cookies.
  GURL new_first_party_for_cookies;

  // The new HTTP referrer header.
  std::string new_referrer;

  // The new referrer policy that should be obeyed if there are
  // subsequent redirects.
  URLRequest::ReferrerPolicy new_referrer_policy;

  // The hostname of the referrer if it asked the client to include a referred
  // Token Binding when following the redirect; otherwise this is the empty
  // string.
  std::string referred_token_binding_host;
};

}  // namespace net

#endif  // NET_URL_REQUEST_REDIRECT_INFO_H_
