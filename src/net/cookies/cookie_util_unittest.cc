// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include "base/strings/string_split.h"
#include "net/cookies/cookie_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

struct RequestCookieParsingTest {
  std::string str;
  base::StringPairs parsed;
};

cookie_util::ParsedRequestCookies MakeParsedRequestCookies(
    const base::StringPairs& data) {
  cookie_util::ParsedRequestCookies parsed;
  for (size_t i = 0; i < data.size(); i++) {
    parsed.push_back(std::make_pair(base::StringPiece(data[i].first),
                                    base::StringPiece(data[i].second)));
  }
  return parsed;
}

void CheckParse(const std::string& str,
                const base::StringPairs& parsed_expected) {
  cookie_util::ParsedRequestCookies parsed;
  cookie_util::ParseRequestCookieLine(str, &parsed);
  EXPECT_EQ(MakeParsedRequestCookies(parsed_expected), parsed);
}

void CheckSerialize(const base::StringPairs& parsed,
                    const std::string& str_expected) {
  cookie_util::ParsedRequestCookies prc = MakeParsedRequestCookies(parsed);
  EXPECT_EQ(str_expected, cookie_util::SerializeRequestCookieLine(prc));
}

TEST(CookieUtilTest, TestDomainIsHostOnly) {
  const struct {
    const char* str;
    const bool is_host_only;
  } tests[] = {
    { "",               true },
    { "www.google.com", true },
    { ".google.com",    false }
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    EXPECT_EQ(tests[i].is_host_only,
              cookie_util::DomainIsHostOnly(tests[i].str));
  }
}

TEST(CookieUtilTest, TestCookieDateParsing) {
  const struct {
    const char* str;
    const bool valid;
    const time_t epoch;
  } tests[] = {
    { "Sat, 15-Apr-17 21:01:22 GMT",           true, 1492290082 },
    { "Thu, 19-Apr-2007 16:00:00 GMT",         true, 1176998400 },
    { "Wed, 25 Apr 2007 21:02:13 GMT",         true, 1177534933 },
    { "Thu, 19/Apr\\2007 16:00:00 GMT",        true, 1176998400 },
    { "Fri, 1 Jan 2010 01:01:50 GMT",          true, 1262307710 },
    { "Wednesday, 1-Jan-2003 00:00:00 GMT",    true, 1041379200 },
    { ", 1-Jan-2003 00:00:00 GMT",             true, 1041379200 },
    { " 1-Jan-2003 00:00:00 GMT",              true, 1041379200 },
    { "1-Jan-2003 00:00:00 GMT",               true, 1041379200 },
    { "Wed,18-Apr-07 22:50:12 GMT",            true, 1176936612 },
    { "WillyWonka  , 18-Apr-07 22:50:12 GMT",  true, 1176936612 },
    { "WillyWonka  , 18-Apr-07 22:50:12",      true, 1176936612 },
    { "WillyWonka  ,  18-apr-07   22:50:12",   true, 1176936612 },
    { "Mon, 18-Apr-1977 22:50:13 GMT",         true, 230251813 },
    { "Mon, 18-Apr-77 22:50:13 GMT",           true, 230251813 },
    // If the cookie came in with the expiration quoted (which in terms of
    // the RFC you shouldn't do), we will get string quoted.  Bug 1261605.
    { "\"Sat, 15-Apr-17\\\"21:01:22\\\"GMT\"", true, 1492290082 },
    // Test with full month names and partial names.
    { "Partyday, 18- April-07 22:50:12",       true, 1176936612 },
    { "Partyday, 18 - Apri-07 22:50:12",       true, 1176936612 },
    { "Wednes, 1-Januar-2003 00:00:00 GMT",    true, 1041379200 },
    // Test that we always take GMT even with other time zones or bogus
    // values.  The RFC says everything should be GMT, and in the worst case
    // we are 24 hours off because of zone issues.
    { "Sat, 15-Apr-17 21:01:22",               true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT-2",         true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT BLAH",      true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT-0400",      true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)",true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 DST",           true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 -0400",         true, 1492290082 },
    { "Sat, 15-Apr-17 21:01:22 (hello there)", true, 1492290082 },
    // Test that if we encounter multiple : fields, that we take the first
    // that correctly parses.
    { "Sat, 15-Apr-17 21:01:22 11:22:33",      true, 1492290082 },
    { "Sat, 15-Apr-17 ::00 21:01:22",          true, 1492290082 },
    { "Sat, 15-Apr-17 boink:z 21:01:22",       true, 1492290082 },
    // We take the first, which in this case is invalid.
    { "Sat, 15-Apr-17 91:22:33 21:01:22",      false, 0 },
    // amazon.com formats their cookie expiration like this.
    { "Thu Apr 18 22:50:12 2007 GMT",          true, 1176936612 },
    // Test that hh:mm:ss can occur anywhere.
    { "22:50:12 Thu Apr 18 2007 GMT",          true, 1176936612 },
    { "Thu 22:50:12 Apr 18 2007 GMT",          true, 1176936612 },
    { "Thu Apr 22:50:12 18 2007 GMT",          true, 1176936612 },
    { "Thu Apr 18 22:50:12 2007 GMT",          true, 1176936612 },
    { "Thu Apr 18 2007 22:50:12 GMT",          true, 1176936612 },
    { "Thu Apr 18 2007 GMT 22:50:12",          true, 1176936612 },
    // Test that the day and year can be anywhere if they are unambigious.
    { "Sat, 15-Apr-17 21:01:22 GMT",           true, 1492290082 },
    { "15-Sat, Apr-17 21:01:22 GMT",           true, 1492290082 },
    { "15-Sat, Apr 21:01:22 GMT 17",           true, 1492290082 },
    { "15-Sat, Apr 21:01:22 GMT 2017",         true, 1492290082 },
    { "15 Apr 21:01:22 2017",                  true, 1492290082 },
    { "15 17 Apr 21:01:22",                    true, 1492290082 },
    { "Apr 15 17 21:01:22",                    true, 1492290082 },
    { "Apr 15 21:01:22 17",                    true, 1492290082 },
    { "2017 April 15 21:01:22",                true, 1492290082 },
    { "15 April 2017 21:01:22",                true, 1492290082 },
    // Some invalid dates
    { "98 April 17 21:01:22",                    false, 0 },
    { "Thu, 012-Aug-2008 20:49:07 GMT",          false, 0 },
    { "Thu, 12-Aug-31841 20:49:07 GMT",          false, 0 },
    { "Thu, 12-Aug-9999999999 20:49:07 GMT",     false, 0 },
    { "Thu, 999999999999-Aug-2007 20:49:07 GMT", false, 0 },
    { "Thu, 12-Aug-2007 20:61:99999999999 GMT",  false, 0 },
    { "IAintNoDateFool",                         false, 0 },
  };

  base::Time parsed_time;
  for (size_t i = 0; i < arraysize(tests); ++i) {
    parsed_time = cookie_util::ParseCookieTime(tests[i].str);
    if (!tests[i].valid) {
      EXPECT_TRUE(parsed_time.is_null()) << tests[i].str;
      continue;
    }
    EXPECT_TRUE(!parsed_time.is_null()) << tests[i].str;
    EXPECT_EQ(tests[i].epoch, parsed_time.ToTimeT()) << tests[i].str;
  }
}

TEST(CookieUtilTest, TestRequestCookieParsing) {
  std::vector<RequestCookieParsingTest> tests;

  // Simple case.
  tests.push_back(RequestCookieParsingTest());
  tests.back().str = "key=value";
  tests.back().parsed.push_back(std::make_pair(std::string("key"),
                                               std::string("value")));
  // Multiple key/value pairs.
  tests.push_back(RequestCookieParsingTest());
  tests.back().str = "key1=value1; key2=value2";
  tests.back().parsed.push_back(std::make_pair(std::string("key1"),
                                               std::string("value1")));
  tests.back().parsed.push_back(std::make_pair(std::string("key2"),
                                               std::string("value2")));
  // Empty value.
  tests.push_back(RequestCookieParsingTest());
  tests.back().str = "key=; otherkey=1234";
  tests.back().parsed.push_back(std::make_pair(std::string("key"),
                                               std::string()));
  tests.back().parsed.push_back(std::make_pair(std::string("otherkey"),
                                               std::string("1234")));
  // Special characters (including equals signs) in value.
  tests.push_back(RequestCookieParsingTest());
  tests.back().str = "key=; a2=s=(./&t=:&u=a#$; a3=+~";
  tests.back().parsed.push_back(std::make_pair(std::string("key"),
                                               std::string()));
  tests.back().parsed.push_back(std::make_pair(std::string("a2"),
                                               std::string("s=(./&t=:&u=a#$")));
  tests.back().parsed.push_back(std::make_pair(std::string("a3"),
                                               std::string("+~")));
  // Quoted value.
  tests.push_back(RequestCookieParsingTest());
  tests.back().str = "key=\"abcdef\"; otherkey=1234";
  tests.back().parsed.push_back(std::make_pair(std::string("key"),
                                               std::string("\"abcdef\"")));
  tests.back().parsed.push_back(std::make_pair(std::string("otherkey"),
                                               std::string("1234")));

  for (size_t i = 0; i < tests.size(); i++) {
    SCOPED_TRACE(testing::Message() << "Test " << i);
    CheckParse(tests[i].str, tests[i].parsed);
    CheckSerialize(tests[i].parsed, tests[i].str);
  }
}

TEST(CookieUtilTest, TestGetEffectiveDomain) {
  // Note: registry_controlled_domains::GetDomainAndRegistry is tested in its
  // own unittests.
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("http", "www.example.com"));
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("https", "www.example.com"));
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("ws", "www.example.com"));
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("wss", "www.example.com"));
  EXPECT_EQ("www.example.com",
            cookie_util::GetEffectiveDomain("ftp", "www.example.com"));
}

}  // namespace

}  // namespace net
