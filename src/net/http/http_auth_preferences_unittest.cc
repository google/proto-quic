// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_preferences.h"

#include <string>
#include <vector>

#include "base/callback.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(HttpAuthPreferencesTest, AuthSchemes) {
  const char* const expected_schemes[] = {"scheme1", "scheme2"};
  std::vector<std::string> expected_schemes_vector(
      expected_schemes, expected_schemes + arraysize(expected_schemes));
  HttpAuthPreferences http_auth_preferences(expected_schemes_vector
#if defined(OS_POSIX) && !defined(OS_ANDROID)
                                            ,
                                            ""
#endif
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  EXPECT_TRUE(http_auth_preferences.IsSupportedScheme("scheme1"));
  EXPECT_TRUE(http_auth_preferences.IsSupportedScheme("scheme2"));
  EXPECT_FALSE(http_auth_preferences.IsSupportedScheme("scheme3"));
}

TEST(HttpAuthPreferencesTest, DisableCnameLookup) {
  std::vector<std::string> auth_schemes;
  HttpAuthPreferences http_auth_preferences(auth_schemes
#if defined(OS_POSIX) && !defined(OS_ANDROID)
                                            ,
                                            ""
#endif
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  EXPECT_FALSE(http_auth_preferences.NegotiateDisableCnameLookup());
  http_auth_preferences.set_negotiate_disable_cname_lookup(true);
  EXPECT_TRUE(http_auth_preferences.NegotiateDisableCnameLookup());
}

TEST(HttpAuthPreferencesTest, NegotiateEnablePort) {
  std::vector<std::string> auth_schemes;
  HttpAuthPreferences http_auth_preferences(auth_schemes
#if defined(OS_POSIX) && !defined(OS_ANDROID)
                                            ,
                                            ""
#endif
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  EXPECT_FALSE(http_auth_preferences.NegotiateEnablePort());
  http_auth_preferences.set_negotiate_enable_port(true);
  EXPECT_TRUE(http_auth_preferences.NegotiateEnablePort());
}

#if defined(OS_ANDROID)
TEST(HttpAuthPreferencesTest, AuthAndroidhNegotiateAccountType) {
  std::vector<std::string> auth_schemes;
  HttpAuthPreferences http_auth_preferences(auth_schemes
#if defined(OS_POSIX) && !defined(OS_ANDROID)
                                            ,
                                            ""
#endif
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  EXPECT_EQ(std::string(),
            http_auth_preferences.AuthAndroidNegotiateAccountType());
  http_auth_preferences.set_auth_android_negotiate_account_type("foo");
  EXPECT_EQ(std::string("foo"),
            http_auth_preferences.AuthAndroidNegotiateAccountType());
}
#endif

#if defined(OS_POSIX) && !defined(OS_ANDROID)
TEST(HttpAuthPreferencesTest, GssApiLibraryName) {
  std::vector<std::string> AuthSchemes;
  HttpAuthPreferences http_auth_preferences(AuthSchemes, "bar"
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  EXPECT_EQ(std::string("bar"), http_auth_preferences.GssapiLibraryName());
}
#endif

#if defined(OS_CHROMEOS)
TEST(HttpAuthPreferencesTest, AllowGssapiLibraryLoadTrue) {
  std::vector<std::string> AuthSchemes;
  HttpAuthPreferences http_auth_preferences(AuthSchemes, "foo", true);
  EXPECT_TRUE(http_auth_preferences.AllowGssapiLibraryLoad());
}
#endif

#if defined(OS_CHROMEOS)
TEST(HttpAuthPreferencesTest, AllowGssapiLibraryLoadFalse) {
  std::vector<std::string> AuthSchemes;
  HttpAuthPreferences http_auth_preferences(AuthSchemes, "foo", false);
  EXPECT_FALSE(http_auth_preferences.AllowGssapiLibraryLoad());
}
#endif

TEST(HttpAuthPreferencesTest, AuthServerWhitelist) {
  std::vector<std::string> auth_schemes;
  HttpAuthPreferences http_auth_preferences(auth_schemes
#if defined(OS_POSIX) && !defined(OS_ANDROID)
                                            ,
                                            ""
#endif
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  // Check initial value
  EXPECT_FALSE(http_auth_preferences.CanUseDefaultCredentials(GURL("abc")));
  http_auth_preferences.set_server_whitelist("*");
  EXPECT_TRUE(http_auth_preferences.CanUseDefaultCredentials(GURL("abc")));
}

TEST(HttpAuthPreferencesTest, AuthDelegateWhitelist) {
  std::vector<std::string> auth_schemes;
  HttpAuthPreferences http_auth_preferences(auth_schemes
#if defined(OS_POSIX) && !defined(OS_ANDROID)
                                            ,
                                            ""
#endif
#if defined(OS_CHROMEOS)
                                            ,
                                            true
#endif
                                            );
  // Check initial value
  EXPECT_FALSE(http_auth_preferences.CanDelegate(GURL("abc")));
  http_auth_preferences.set_delegate_whitelist("*");
  EXPECT_TRUE(http_auth_preferences.CanDelegate(GURL("abc")));
}

}  // namespace net
