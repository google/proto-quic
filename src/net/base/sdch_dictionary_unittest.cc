// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/sdch_dictionary.h"

#include <set>
#include <string>

#include "net/base/sdch_problem_codes.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(SdchDictionaryTest, CanSet) {
  SdchProblemCode (*CanSet)(const std::string& domain, const std::string& path,
                            const std::set<int>& ports,
                            const GURL& dictionary_url) =
      SdchDictionary::CanSet;

  std::set<int> single_port;
  single_port.insert(1);

  std::set<int> dual_port;
  dual_port.insert(2);
  dual_port.insert(3);

  // Not testing specific error codes; that's implementation, not behavior.
  EXPECT_EQ(SDCH_OK, CanSet("www.google.com", "", std::set<int>(),
                            GURL("http://www.google.com/dictionary")));
  EXPECT_NE(SDCH_OK, CanSet("", "", std::set<int>(),
                            GURL("http://www.google.com/dictionary")));
  EXPECT_NE(SDCH_OK,
            CanSet("com", "", std::set<int>(), GURL("http://com/dictionary")));
  EXPECT_NE(SDCH_OK, CanSet("www.google.com", "", std::set<int>(),
                            GURL("http://www.simple.com/dictionary")));
  EXPECT_EQ(SDCH_OK, CanSet(".google.com", "", std::set<int>(),
                            GURL("http://www.google.com/dictionary")));
  EXPECT_NE(SDCH_OK, CanSet("google.com", "", std::set<int>(),
                            GURL("http://www.google.com/dictionary")));
  EXPECT_EQ(SDCH_OK, CanSet("www.google.com", "", single_port,
                            GURL("http://www.google.com:1/dictionary")));
  EXPECT_EQ(SDCH_OK, CanSet("www.google.com", "", dual_port,
                            GURL("http://www.google.com:2/dictionary")));
  EXPECT_NE(SDCH_OK, CanSet("www.google.com", "", single_port,
                            GURL("http://www.google.com:10/dictionary")));
  EXPECT_NE(SDCH_OK, CanSet("www.google.com", "", dual_port,
                            GURL("http://www.google.com:10/dictionary")));
}

TEST(SdchDictionaryTest, CanUse) {
  std::set<int> dual_port;
  dual_port.insert(2);
  dual_port.insert(3);

  SdchDictionary test_dictionary_1(
      "xyzzy", 0u,  // text, offset
      "ch", "sh",   // client hash, server hash
      GURL("http://www.example.com"), "www.example.com",
      "/url",                                               // domain, path
      base::Time::Now() + base::TimeDelta::FromSeconds(1),  // expiration
      dual_port);                                           // ports

  // Not testing specific error codes; that's implementation, not behavior.
  EXPECT_EQ(SDCH_OK,
            test_dictionary_1.CanUse(GURL("http://www.example.com:2/url")));
  EXPECT_NE(SDCH_OK,
            test_dictionary_1.CanUse(GURL("http://www.google.com:2/url")));
  EXPECT_NE(SDCH_OK,
            test_dictionary_1.CanUse(GURL("http://www.example.com:4/url")));
  EXPECT_NE(SDCH_OK,
            test_dictionary_1.CanUse(GURL("http://www.example.com:2/wurl")));
  EXPECT_NE(SDCH_OK,
            test_dictionary_1.CanUse(GURL("https://www.example.com:2/url")));
  EXPECT_NE(SDCH_OK,
            test_dictionary_1.CanUse(GURL("ws://www.example.com:2/url")));
}

TEST(SdchDictionaryTest, PathMatch) {
  bool (*PathMatch)(const std::string& path, const std::string& restriction) =
      SdchDictionary::PathMatch;
  // Perfect match is supported.
  EXPECT_TRUE(PathMatch("/search", "/search"));
  EXPECT_TRUE(PathMatch("/search/", "/search/"));

  // Prefix only works if last character of restriction is a slash, or first
  // character in path after a match is a slash. Validate each case separately.

  // Rely on the slash in the path (not at the end of the restriction).
  EXPECT_TRUE(PathMatch("/search/something", "/search"));
  EXPECT_TRUE(PathMatch("/search/s", "/search"));
  EXPECT_TRUE(PathMatch("/search/other", "/search"));
  EXPECT_TRUE(PathMatch("/search/something", "/search"));

  // Rely on the slash at the end of the restriction.
  EXPECT_TRUE(PathMatch("/search/something", "/search/"));
  EXPECT_TRUE(PathMatch("/search/s", "/search/"));
  EXPECT_TRUE(PathMatch("/search/other", "/search/"));
  EXPECT_TRUE(PathMatch("/search/something", "/search/"));

  // Make sure less that sufficient prefix match is false.
  EXPECT_FALSE(PathMatch("/sear", "/search"));
  EXPECT_FALSE(PathMatch("/", "/search"));
  EXPECT_FALSE(PathMatch(std::string(), "/search"));

  // Add examples with several levels of direcories in the restriction.
  EXPECT_FALSE(PathMatch("/search/something", "search/s"));
  EXPECT_FALSE(PathMatch("/search/", "/search/s"));

  // Make sure adding characters to path will also fail.
  EXPECT_FALSE(PathMatch("/searching", "/search/"));
  EXPECT_FALSE(PathMatch("/searching", "/search"));

  // Make sure we're case sensitive.
  EXPECT_FALSE(PathMatch("/ABC", "/abc"));
  EXPECT_FALSE(PathMatch("/abc", "/ABC"));
}

TEST(SdchDictionaryTest, Expired) {
  EXPECT_TRUE(
      SdchDictionary("xyzzy", 0u, "ch", "sh", GURL("http://www.example.com"),
                     "www.example.com", "/url",
                     base::Time::Now() - base::TimeDelta::FromSeconds(1),
                     std::set<int>()).Expired());
  EXPECT_FALSE(
      SdchDictionary("xyzzy", 0u, "ch", "sh", GURL("http://www.example.com"),
                     "www.example.com", "/url",
                     base::Time::Now() + base::TimeDelta::FromSeconds(1),
                     std::set<int>()).Expired());
}

}  // namespace net
