// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace {
namespace test1 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest1-inc.cc"
}
namespace test2 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest2-inc.cc"
}
namespace test3 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest3-inc.cc"
}
namespace test4 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest4-inc.cc"
}
namespace test5 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest5-inc.cc"
}
namespace test6 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest6-inc.cc"
}
}  // namespace

namespace net {
namespace registry_controlled_domains {
namespace {

std::string GetDomainFromURL(const std::string& url) {
  return GetDomainAndRegistry(GURL(url), EXCLUDE_PRIVATE_REGISTRIES);
}

std::string GetDomainFromHost(const std::string& host) {
  return GetDomainAndRegistry(host, EXCLUDE_PRIVATE_REGISTRIES);
}

size_t GetRegistryLengthFromURL(
    const std::string& url,
    UnknownRegistryFilter unknown_filter) {
  return GetRegistryLength(GURL(url),
                           unknown_filter,
                           EXCLUDE_PRIVATE_REGISTRIES);
}

size_t GetRegistryLengthFromURLIncludingPrivate(
    const std::string& url,
    UnknownRegistryFilter unknown_filter) {
  return GetRegistryLength(GURL(url),
                           unknown_filter,
                           INCLUDE_PRIVATE_REGISTRIES);
}

size_t GetRegistryLengthFromHost(
    const std::string& host,
    UnknownRegistryFilter unknown_filter) {
  return GetRegistryLength(host, unknown_filter, EXCLUDE_PRIVATE_REGISTRIES);
}

size_t GetRegistryLengthFromHostIncludingPrivate(
    const std::string& host,
    UnknownRegistryFilter unknown_filter) {
  return GetRegistryLength(host, unknown_filter, INCLUDE_PRIVATE_REGISTRIES);
}

}  // namespace

class RegistryControlledDomainTest : public testing::Test {
 protected:
  template <typename Graph>
  void UseDomainData(const Graph& graph) {
    SetFindDomainGraph(graph, sizeof(Graph));
  }

  bool CompareDomains(const std::string& url1, const std::string& url2) {
    SCOPED_TRACE(url1 + " " + url2);
    GURL g1 = GURL(url1);
    GURL g2 = GURL(url2);
    url::Origin o1 = url::Origin(g1);
    url::Origin o2 = url::Origin(g2);
    EXPECT_EQ(SameDomainOrHost(o1, o2, EXCLUDE_PRIVATE_REGISTRIES),
              SameDomainOrHost(g1, g2, EXCLUDE_PRIVATE_REGISTRIES));
    return SameDomainOrHost(g1, g2, EXCLUDE_PRIVATE_REGISTRIES);
  }

  void TearDown() override { SetFindDomainGraph(); }
};

TEST_F(RegistryControlledDomainTest, TestGetDomainAndRegistry) {
  UseDomainData(test1::kDafsa);

  // Test GURL version of GetDomainAndRegistry().
  EXPECT_EQ("baz.jp", GetDomainFromURL("http://a.baz.jp/file.html"));    // 1
  EXPECT_EQ("baz.jp.", GetDomainFromURL("http://a.baz.jp./file.html"));  // 1
  EXPECT_EQ("", GetDomainFromURL("http://ac.jp"));                       // 2
  EXPECT_EQ("", GetDomainFromURL("http://a.bar.jp"));                    // 3
  EXPECT_EQ("", GetDomainFromURL("http://bar.jp"));                      // 3
  EXPECT_EQ("", GetDomainFromURL("http://baz.bar.jp"));                  // 3 4
  EXPECT_EQ("a.b.baz.bar.jp", GetDomainFromURL("http://a.b.baz.bar.jp"));
                                                                         // 4
  EXPECT_EQ("pref.bar.jp", GetDomainFromURL("http://baz.pref.bar.jp"));  // 5
  EXPECT_EQ("b.bar.baz.com.", GetDomainFromURL("http://a.b.bar.baz.com."));
                                                                         // 6
  EXPECT_EQ("a.d.c", GetDomainFromURL("http://a.d.c"));                  // 7
  EXPECT_EQ("a.d.c", GetDomainFromURL("http://.a.d.c"));                 // 7
  EXPECT_EQ("a.d.c", GetDomainFromURL("http://..a.d.c"));                // 7
  EXPECT_EQ("b.c", GetDomainFromURL("http://a.b.c"));                    // 7 8
  EXPECT_EQ("baz.com", GetDomainFromURL("http://baz.com"));              // none
  EXPECT_EQ("baz.com.", GetDomainFromURL("http://baz.com."));            // none

  EXPECT_EQ("", GetDomainFromURL(std::string()));
  EXPECT_EQ("", GetDomainFromURL("http://"));
  EXPECT_EQ("", GetDomainFromURL("file:///C:/file.html"));
  EXPECT_EQ("", GetDomainFromURL("http://foo.com.."));
  EXPECT_EQ("", GetDomainFromURL("http://..."));
  EXPECT_EQ("", GetDomainFromURL("http://192.168.0.1"));
  EXPECT_EQ("", GetDomainFromURL("http://localhost"));
  EXPECT_EQ("", GetDomainFromURL("http://localhost."));
  EXPECT_EQ("", GetDomainFromURL("http:////Comment"));

  // Test std::string version of GetDomainAndRegistry().  Uses the same
  // underpinnings as the GURL version, so this is really more of a check of
  // CanonicalizeHost().
  EXPECT_EQ("baz.jp", GetDomainFromHost("a.baz.jp"));                  // 1
  EXPECT_EQ("baz.jp.", GetDomainFromHost("a.baz.jp."));                // 1
  EXPECT_EQ("", GetDomainFromHost("ac.jp"));                           // 2
  EXPECT_EQ("", GetDomainFromHost("a.bar.jp"));                        // 3
  EXPECT_EQ("", GetDomainFromHost("bar.jp"));                          // 3
  EXPECT_EQ("", GetDomainFromHost("baz.bar.jp"));                      // 3 4
  EXPECT_EQ("a.b.baz.bar.jp", GetDomainFromHost("a.b.baz.bar.jp"));    // 3 4
  EXPECT_EQ("pref.bar.jp", GetDomainFromHost("baz.pref.bar.jp"));      // 5
  EXPECT_EQ("b.bar.baz.com.", GetDomainFromHost("a.b.bar.baz.com."));  // 6
  EXPECT_EQ("a.d.c", GetDomainFromHost("a.d.c"));                      // 7
  EXPECT_EQ("a.d.c", GetDomainFromHost(".a.d.c"));                     // 7
  EXPECT_EQ("a.d.c", GetDomainFromHost("..a.d.c"));                    // 7
  EXPECT_EQ("b.c", GetDomainFromHost("a.b.c"));                        // 7 8
  EXPECT_EQ("baz.com", GetDomainFromHost("baz.com"));                  // none
  EXPECT_EQ("baz.com.", GetDomainFromHost("baz.com."));                // none

  EXPECT_EQ("", GetDomainFromHost(std::string()));
  EXPECT_EQ("", GetDomainFromHost("foo.com.."));
  EXPECT_EQ("", GetDomainFromHost("..."));
  EXPECT_EQ("", GetDomainFromHost("192.168.0.1"));
  EXPECT_EQ("", GetDomainFromHost("localhost."));
  EXPECT_EQ("", GetDomainFromHost(".localhost."));
}

TEST_F(RegistryControlledDomainTest, TestGetRegistryLength) {
  UseDomainData(test1::kDafsa);

  // Test GURL version of GetRegistryLength().
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://a.baz.jp/file.html",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 1
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://a.baz.jp./file.html",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 1
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://ac.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 2
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://a.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 3
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 3
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://baz.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 3 4
  EXPECT_EQ(12U, GetRegistryLengthFromURL("http://a.b.baz.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 4
  EXPECT_EQ(6U, GetRegistryLengthFromURL("http://baz.pref.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 5
  EXPECT_EQ(11U, GetRegistryLengthFromURL("http://a.b.bar.baz.com",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 6
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://a.d.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 7
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://.a.d.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 7
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://..a.d.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 7
  EXPECT_EQ(1U, GetRegistryLengthFromURL("http://a.b.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // 7 8
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://baz.com",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // none
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://baz.com.",
                                         EXCLUDE_UNKNOWN_REGISTRIES)); // none
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://baz.com",
                                         INCLUDE_UNKNOWN_REGISTRIES)); // none
  EXPECT_EQ(4U, GetRegistryLengthFromURL("http://baz.com.",
                                         INCLUDE_UNKNOWN_REGISTRIES)); // none

  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromURL(std::string(), EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromURL("http://", EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromURL("file:///C:/file.html",
                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://foo.com..",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://...",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://192.168.0.1",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost",
                                         INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost.",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost.",
                                         INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http:////Comment",
                                         EXCLUDE_UNKNOWN_REGISTRIES));

  // Test std::string version of GetRegistryLength().  Uses the same
  // underpinnings as the GURL version, so this is really more of a check of
  // CanonicalizeHost().
  EXPECT_EQ(2U, GetRegistryLengthFromHost("a.baz.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(3U, GetRegistryLengthFromHost("a.baz.jp.",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(0U, GetRegistryLengthFromHost("ac.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 2
  EXPECT_EQ(0U, GetRegistryLengthFromHost("a.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(0U, GetRegistryLengthFromHost("bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(0U, GetRegistryLengthFromHost("baz.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 3 4
  EXPECT_EQ(12U, GetRegistryLengthFromHost("a.b.baz.bar.jp",
                                           EXCLUDE_UNKNOWN_REGISTRIES)); // 4
  EXPECT_EQ(6U, GetRegistryLengthFromHost("baz.pref.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(11U, GetRegistryLengthFromHost("a.b.bar.baz.com",
                                           EXCLUDE_UNKNOWN_REGISTRIES)); // 6
  EXPECT_EQ(3U, GetRegistryLengthFromHost("a.d.c",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(3U, GetRegistryLengthFromHost(".a.d.c",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(3U, GetRegistryLengthFromHost("..a.d.c",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(1U, GetRegistryLengthFromHost("a.b.c",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 7 8
  EXPECT_EQ(0U, GetRegistryLengthFromHost("baz.com",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(0U, GetRegistryLengthFromHost("baz.com.",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(3U, GetRegistryLengthFromHost("baz.com",
                                          INCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(4U, GetRegistryLengthFromHost("baz.com.",
                                          INCLUDE_UNKNOWN_REGISTRIES));  // none

  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromHost(std::string(), EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("foo.com..",
                                          EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("..",
                                          EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("192.168.0.1",
                                          EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("localhost",
                                          EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("localhost",
                                          INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("localhost.",
                                          EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost("localhost.",
                                          INCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestSameDomainOrHost) {
  UseDomainData(test2::kDafsa);

  EXPECT_TRUE(CompareDomains("http://a.b.bar.jp/file.html",
                             "http://a.b.bar.jp/file.html"));  // b.bar.jp
  EXPECT_TRUE(CompareDomains("http://a.b.bar.jp/file.html",
                             "http://b.b.bar.jp/file.html"));  // b.bar.jp
  EXPECT_FALSE(CompareDomains("http://a.foo.jp/file.html",     // foo.jp
                              "http://a.not.jp/file.html"));   // not.jp
  EXPECT_FALSE(CompareDomains("http://a.foo.jp/file.html",     // foo.jp
                              "http://a.foo.jp./file.html"));  // foo.jp.
  EXPECT_FALSE(CompareDomains("http://a.com/file.html",        // a.com
                              "http://b.com/file.html"));      // b.com
  EXPECT_TRUE(CompareDomains("http://a.x.com/file.html",
                             "http://b.x.com/file.html"));     // x.com
  EXPECT_TRUE(CompareDomains("http://a.x.com/file.html",
                             "http://.x.com/file.html"));      // x.com
  EXPECT_TRUE(CompareDomains("http://a.x.com/file.html",
                             "http://..b.x.com/file.html"));   // x.com
  EXPECT_TRUE(CompareDomains("http://intranet/file.html",
                             "http://intranet/file.html"));    // intranet
  EXPECT_TRUE(CompareDomains("http://127.0.0.1/file.html",
                             "http://127.0.0.1/file.html"));   // 127.0.0.1
  EXPECT_FALSE(CompareDomains("http://192.168.0.1/file.html",  // 192.168.0.1
                              "http://127.0.0.1/file.html"));  // 127.0.0.1
  EXPECT_FALSE(CompareDomains("file:///C:/file.html",
                              "file:///C:/file.html"));        // no host
}

TEST_F(RegistryControlledDomainTest, TestDefaultData) {
  // Note that no data is set: we're using the default rules.
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://google.com",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://stanford.edu",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://ustreas.gov",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://icann.net",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://ferretcentral.org",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://nowhere.notavaliddomain",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(15U, GetRegistryLengthFromURL("http://nowhere.notavaliddomain",
                                         INCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestPrivateRegistryHandling) {
  UseDomainData(test1::kDafsa);

  // Testing the same dataset for INCLUDE_PRIVATE_REGISTRIES and
  // EXCLUDE_PRIVATE_REGISTRIES arguments.
  // For the domain data used for this test, the private registries are
  // 'priv.no' and 'private'.

  // Non-private registries.
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://priv.no",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://foo.priv.no",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://foo.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://www.foo.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://private",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://foo.private",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://private",
                                         INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U, GetRegistryLengthFromURL("http://foo.private",
                                         INCLUDE_UNKNOWN_REGISTRIES));

  // Private registries.
  EXPECT_EQ(0U,
      GetRegistryLengthFromURLIncludingPrivate("http://priv.no",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.priv.no",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.jp",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U,
      GetRegistryLengthFromURLIncludingPrivate("http://www.foo.jp",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
      GetRegistryLengthFromURLIncludingPrivate("http://private",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.private",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
      GetRegistryLengthFromURLIncludingPrivate("http://private",
                                               INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.private",
                                               INCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaTwoByteOffsets) {
  UseDomainData(test3::kDafsa);

  // Testing to lookup keys in a DAFSA with two byte offsets.
  // This DAFSA is constructed so that labels begin and end with unique
  // characters, which makes it impossible to merge labels. Each inner node
  // is about 100 bytes and a one byte offset can at most add 64 bytes to
  // previous offset. Thus the paths must go over two byte offsets.

  const char key0[] =
      "a.b.6____________________________________________________"
      "________________________________________________6";
  const char key1[] =
      "a.b.7____________________________________________________"
      "________________________________________________7";
  const char key2[] =
      "a.b.a____________________________________________________"
      "________________________________________________8";

  EXPECT_EQ(102U, GetRegistryLengthFromHost(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(102U,
            GetRegistryLengthFromHostIncludingPrivate(
                key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key2, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaThreeByteOffsets) {
  UseDomainData(test4::kDafsa);

  // Testing to lookup keys in a DAFSA with three byte offsets.
  // This DAFSA is constructed so that labels begin and end with unique
  // characters, which makes it impossible to merge labels. The byte array
  // has a size of ~54k. A two byte offset can add at most add 8k to the
  // previous offset. Since we can skip only forward in memory, the nodes
  // representing the return values must be located near the end of the byte
  // array. The probability that we can reach from an arbitrary inner node to
  // a return value without using a three byte offset is small (but not zero).
  // The test is repeated with some different keys and with a reasonable
  // probability at least one of the tested paths has go over a three byte
  // offset.

  const char key0[] =
      "a.b.Z6___________________________________________________"
      "_________________________________________________Z6";
  const char key1[] =
      "a.b.Z7___________________________________________________"
      "_________________________________________________Z7";
  const char key2[] =
      "a.b.Za___________________________________________________"
      "_________________________________________________Z8";

  EXPECT_EQ(104U, GetRegistryLengthFromHost(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(104U,
            GetRegistryLengthFromHostIncludingPrivate(
                key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key2, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaJoinedPrefixes) {
  UseDomainData(test5::kDafsa);

  // Testing to lookup keys in a DAFSA with compressed prefixes.
  // This DAFSA is constructed from words with similar prefixes but distinct
  // suffixes. The DAFSA will then form a trie with the implicit source node
  // as root.

  const char key0[] = "a.b.ai";
  const char key1[] = "a.b.bj";
  const char key2[] = "a.b.aak";
  const char key3[] = "a.b.bbl";
  const char key4[] = "a.b.aaa";
  const char key5[] = "a.b.bbb";
  const char key6[] = "a.b.aaaam";
  const char key7[] = "a.b.bbbbn";

  EXPECT_EQ(2U, GetRegistryLengthFromHost(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U,
            GetRegistryLengthFromHostIncludingPrivate(
                key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromHost(key2, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key3, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U,
            GetRegistryLengthFromHostIncludingPrivate(
                key3, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetRegistryLengthFromHostIncludingPrivate(
                key4, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetRegistryLengthFromHostIncludingPrivate(
                key5, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(5U, GetRegistryLengthFromHost(key6, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(5U, GetRegistryLengthFromHost(key7, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaJoinedSuffixes) {
  UseDomainData(test6::kDafsa);

  // Testing to lookup keys in a DAFSA with compressed suffixes.
  // This DAFSA is constructed from words with similar suffixes but distinct
  // prefixes. The DAFSA will then form a trie with the implicit sink node as
  // root.

  const char key0[] = "a.b.ia";
  const char key1[] = "a.b.jb";
  const char key2[] = "a.b.kaa";
  const char key3[] = "a.b.lbb";
  const char key4[] = "a.b.aaa";
  const char key5[] = "a.b.bbb";
  const char key6[] = "a.b.maaaa";
  const char key7[] = "a.b.nbbbb";

  EXPECT_EQ(2U, GetRegistryLengthFromHost(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U,
            GetRegistryLengthFromHostIncludingPrivate(
                key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromHost(key2, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromHost(key3, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U,
            GetRegistryLengthFromHostIncludingPrivate(
                key3, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetRegistryLengthFromHostIncludingPrivate(
                key4, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetRegistryLengthFromHostIncludingPrivate(
                key5, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(5U, GetRegistryLengthFromHost(key6, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(5U, GetRegistryLengthFromHost(key7, EXCLUDE_UNKNOWN_REGISTRIES));
}
}  // namespace registry_controlled_domains
}  // namespace net
