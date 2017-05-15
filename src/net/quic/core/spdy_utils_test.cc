// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/quic/core/spdy_utils.h"

#include <memory>

#include "base/macros.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/test/gtest_util.h"

using std::string;
using testing::UnorderedElementsAre;
using testing::Pair;

namespace net {
namespace test {

static std::unique_ptr<QuicHeaderList> FromList(
    const QuicHeaderList::ListType& src) {
  std::unique_ptr<QuicHeaderList> headers(new QuicHeaderList);
  headers->OnHeaderBlockStart();
  for (const auto& p : src) {
    headers->OnHeader(p.first, p.second);
  }
  headers->OnHeaderBlockEnd(0, 0);
  return headers;
}

class SpdyUtilsTest : public QuicTest {};

TEST_F(SpdyUtilsTest, CopyAndValidateHeaders) {
  auto headers = FromList({// All cookie crumbs are joined.
                           {"cookie", " part 1"},
                           {"cookie", "part 2 "},
                           {"cookie", "part3"},

                           // Already-delimited headers are passed through.
                           {"passed-through", string("foo\0baz", 7)},

                           // Other headers are joined on \0.
                           {"joined", "value 1"},
                           {"joined", "value 2"},

                           // Empty headers remain empty.
                           {"empty", ""},

                           // Joined empty headers work as expected.
                           {"empty-joined", ""},
                           {"empty-joined", "foo"},
                           {"empty-joined", ""},
                           {"empty-joined", ""},

                           // Non-continguous cookie crumb.
                           {"cookie", " fin!"}});

  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block,
              UnorderedElementsAre(
                  Pair("cookie", " part 1; part 2 ; part3;  fin!"),
                  Pair("passed-through", QuicStringPiece("foo\0baz", 7)),
                  Pair("joined", QuicStringPiece("value 1\0value 2", 15)),
                  Pair("empty", ""),
                  Pair("empty-joined", QuicStringPiece("\0foo\0\0", 6))));
  EXPECT_EQ(-1, content_length);
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersEmptyName) {
  auto headers = FromList({{"foo", "foovalue"}, {"", "barvalue"}, {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_FALSE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersUpperCaseName) {
  auto headers =
      FromList({{"foo", "foovalue"}, {"bar", "barvalue"}, {"bAz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_FALSE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersMultipleContentLengths) {
  auto headers = FromList({{"content-length", "9"},
                           {"foo", "foovalue"},
                           {"content-length", "9"},
                           {"bar", "barvalue"},
                           {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block, UnorderedElementsAre(
                         Pair("foo", "foovalue"), Pair("bar", "barvalue"),
                         Pair("content-length", QuicStringPiece("9"
                                                                "\0"
                                                                "9",
                                                                3)),
                         Pair("baz", "")));
  EXPECT_EQ(9, content_length);
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersInconsistentContentLengths) {
  auto headers = FromList({{"content-length", "9"},
                           {"foo", "foovalue"},
                           {"content-length", "8"},
                           {"bar", "barvalue"},
                           {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_FALSE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersLargeContentLength) {
  auto headers = FromList({{"content-length", "9000000000"},
                           {"foo", "foovalue"},
                           {"bar", "barvalue"},
                           {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block, UnorderedElementsAre(
                         Pair("foo", "foovalue"), Pair("bar", "barvalue"),
                         Pair("content-length", QuicStringPiece("9000000000")),
                         Pair("baz", "")));
  EXPECT_EQ(9000000000, content_length);
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersMultipleValues) {
  auto headers = FromList({{"foo", "foovalue"},
                           {"bar", "barvalue"},
                           {"baz", ""},
                           {"foo", "boo"},
                           {"baz", "buzz"}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block, UnorderedElementsAre(
                         Pair("foo", QuicStringPiece("foovalue\0boo", 12)),
                         Pair("bar", "barvalue"),
                         Pair("baz", QuicStringPiece("\0buzz", 5))));
  EXPECT_EQ(-1, content_length);
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersMoreThanTwoValues) {
  auto headers = FromList({{"set-cookie", "value1"},
                           {"set-cookie", "value2"},
                           {"set-cookie", "value3"}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(
      block, UnorderedElementsAre(Pair(
                 "set-cookie", QuicStringPiece("value1\0value2\0value3", 20))));
  EXPECT_EQ(-1, content_length);
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersCookie) {
  auto headers = FromList({{"foo", "foovalue"},
                           {"bar", "barvalue"},
                           {"cookie", "value1"},
                           {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block, UnorderedElementsAre(
                         Pair("foo", "foovalue"), Pair("bar", "barvalue"),
                         Pair("cookie", "value1"), Pair("baz", "")));
  EXPECT_EQ(-1, content_length);
}

TEST_F(SpdyUtilsTest, CopyAndValidateHeadersMultipleCookies) {
  auto headers = FromList({{"foo", "foovalue"},
                           {"bar", "barvalue"},
                           {"cookie", "value1"},
                           {"baz", ""},
                           {"cookie", "value2"}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block, UnorderedElementsAre(
                         Pair("foo", "foovalue"), Pair("bar", "barvalue"),
                         Pair("cookie", "value1; value2"), Pair("baz", "")));
  EXPECT_EQ(-1, content_length);
}

TEST_F(SpdyUtilsTest, GetUrlFromHeaderBlock) {
  SpdyHeaderBlock headers;
  EXPECT_EQ(SpdyUtils::GetUrlFromHeaderBlock(headers), "");
  headers[":scheme"] = "https";
  EXPECT_EQ(SpdyUtils::GetUrlFromHeaderBlock(headers), "");
  headers[":authority"] = "www.google.com";
  EXPECT_EQ(SpdyUtils::GetUrlFromHeaderBlock(headers), "");
  headers[":path"] = "/index.html";
  EXPECT_EQ(SpdyUtils::GetUrlFromHeaderBlock(headers),
            "https://www.google.com/index.html");
  headers["key1"] = "value1";
  headers["key2"] = "value2";
  EXPECT_EQ(SpdyUtils::GetUrlFromHeaderBlock(headers),
            "https://www.google.com/index.html");
}

TEST_F(SpdyUtilsTest, GetHostNameFromHeaderBlock) {
  SpdyHeaderBlock headers;
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "");
  headers[":scheme"] = "https";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "");
  headers[":authority"] = "www.google.com";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "");
  headers[":path"] = "/index.html";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "www.google.com");
  headers["key1"] = "value1";
  headers["key2"] = "value2";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "www.google.com");
  headers[":authority"] = "www.google.com:6666";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "www.google.com");
  headers[":authority"] = "192.168.1.1";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "192.168.1.1");
  headers[":authority"] = "192.168.1.1:6666";
  EXPECT_EQ(SpdyUtils::GetHostNameFromHeaderBlock(headers), "192.168.1.1");
}

TEST_F(SpdyUtilsTest, PopulateHeaderBlockFromUrl) {
  string url = "https://www.google.com/index.html";
  SpdyHeaderBlock headers;
  EXPECT_TRUE(SpdyUtils::PopulateHeaderBlockFromUrl(url, &headers));
  EXPECT_EQ("https", headers[":scheme"].as_string());
  EXPECT_EQ("www.google.com", headers[":authority"].as_string());
  EXPECT_EQ("/index.html", headers[":path"].as_string());
}

TEST_F(SpdyUtilsTest, PopulateHeaderBlockFromUrlWithNoPath) {
  string url = "https://www.google.com";
  SpdyHeaderBlock headers;
  EXPECT_TRUE(SpdyUtils::PopulateHeaderBlockFromUrl(url, &headers));
  EXPECT_EQ("https", headers[":scheme"].as_string());
  EXPECT_EQ("www.google.com", headers[":authority"].as_string());
  EXPECT_EQ("/", headers[":path"].as_string());
}

TEST_F(SpdyUtilsTest, PopulateHeaderBlockFromUrlFails) {
  SpdyHeaderBlock headers;
  EXPECT_FALSE(SpdyUtils::PopulateHeaderBlockFromUrl("/", &headers));
  EXPECT_FALSE(SpdyUtils::PopulateHeaderBlockFromUrl("/index.html", &headers));
  EXPECT_FALSE(
      SpdyUtils::PopulateHeaderBlockFromUrl("www.google.com/", &headers));
}

}  // namespace test
}  // namespace net
