// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_store.h"

#include <memory>
#include <vector>

#include "base/time/time.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_options.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

// Helper for testing BuildCookieLine
void MatchCookieLineToVector(
    const std::string& line,
    const std::vector<std::unique_ptr<CanonicalCookie>>& cookies) {
  // Test the std::vector<CanonicalCookie> variant
  // ('CookieMonster::CookieList'):
  std::vector<CanonicalCookie> list;
  for (const auto& cookie : cookies)
    list.push_back(*cookie);
  EXPECT_EQ(line, CookieStore::BuildCookieLine(list));

  // Test the std::vector<CanonicalCookie*> variant
  // ('CookieMonster::CanonicalCookieVector' (yes, this is absurd)):
  std::vector<CanonicalCookie*> ptr_list;
  for (const auto& cookie : cookies)
    ptr_list.push_back(cookie.get());
  EXPECT_EQ(line, CookieStore::BuildCookieLine(ptr_list));
}

} // namespace

TEST(CookieStoreBaseTest, BuildCookieLine) {
  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  GURL url("https://example.com/");
  CookieOptions options;
  base::Time now = base::Time::Now();
  MatchCookieLineToVector("", cookies);

  cookies.push_back(CanonicalCookie::Create(url, "A=B", now, options));
  MatchCookieLineToVector("A=B", cookies);
  // Nameless cookies are sent back without a prefixed '='.
  cookies.push_back(CanonicalCookie::Create(url, "C", now, options));
  MatchCookieLineToVector("A=B; C", cookies);
  // Cookies separated by ';'.
  cookies.push_back(CanonicalCookie::Create(url, "D=E", now, options));
  MatchCookieLineToVector("A=B; C; D=E", cookies);
  // BuildCookieLine doesn't reorder the list, it relies on the caller to do so.
  cookies.push_back(CanonicalCookie::Create(
      url, "F=G", now - base::TimeDelta::FromSeconds(1), options));
  MatchCookieLineToVector("A=B; C; D=E; F=G", cookies);
  // BuildCookieLine doesn't deduplicate.
  cookies.push_back(CanonicalCookie::Create(
      url, "D=E", now - base::TimeDelta::FromSeconds(2), options));
  MatchCookieLineToVector("A=B; C; D=E; F=G; D=E", cookies);
}

}  // namespace net
