// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/static_cookie_policy.h"

#include "base/logging.h"
#include "net/base/net_errors.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "url/gurl.h"

namespace net {

int StaticCookiePolicy::CanGetCookies(
    const GURL& url,
    const GURL& first_party_for_cookies) const {
  switch (type_) {
    case StaticCookiePolicy::ALLOW_ALL_COOKIES:
      return OK;
    case StaticCookiePolicy::BLOCK_ALL_THIRD_PARTY_COOKIES:
      if (first_party_for_cookies.is_empty())
        return OK;  // Empty first-party URL indicates a first-party request.
      return registry_controlled_domains::SameDomainOrHost(
          url,
          first_party_for_cookies,
          registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES) ?
              OK : ERR_ACCESS_DENIED;
    case StaticCookiePolicy::BLOCK_ALL_COOKIES:
      return ERR_ACCESS_DENIED;
    default:
      NOTREACHED();
      return ERR_ACCESS_DENIED;
  }
}

int StaticCookiePolicy::CanSetCookie(
    const GURL& url,
    const GURL& first_party_for_cookies) const {
  switch (type_) {
    case StaticCookiePolicy::ALLOW_ALL_COOKIES:
      return OK;
    case StaticCookiePolicy::BLOCK_ALL_THIRD_PARTY_COOKIES:
      if (first_party_for_cookies.is_empty())
        return OK;  // Empty first-party URL indicates a first-party request.
      return registry_controlled_domains::SameDomainOrHost(
          url,
          first_party_for_cookies,
          registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES) ?
              OK : ERR_ACCESS_DENIED;
    case StaticCookiePolicy::BLOCK_ALL_COOKIES:
      return ERR_ACCESS_DENIED;
    default:
      NOTREACHED();
      return ERR_ACCESS_DENIED;
  }
}

}  // namespace net
