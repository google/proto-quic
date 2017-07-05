// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/quic/core/spdy_utils.h"

#include <memory>

#include "base/macros.h"
#include "net/quic/platform/api/quic_flag_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_string_piece.h"
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

TEST(CopyAndValidateHeaders, NormalUsage) {
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

TEST(CopyAndValidateHeaders, EmptyName) {
  auto headers = FromList({{"foo", "foovalue"}, {"", "barvalue"}, {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_FALSE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
}

TEST(CopyAndValidateHeaders, UpperCaseName) {
  auto headers =
      FromList({{"foo", "foovalue"}, {"bar", "barvalue"}, {"bAz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_FALSE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
}

TEST(CopyAndValidateHeaders, MultipleContentLengths) {
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

TEST(CopyAndValidateHeaders, InconsistentContentLengths) {
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

TEST(CopyAndValidateHeaders, LargeContentLength) {
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

TEST(CopyAndValidateHeaders, MultipleValues) {
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

TEST(CopyAndValidateHeaders, MoreThanTwoValues) {
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

TEST(CopyAndValidateHeaders, Cookie) {
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

TEST(CopyAndValidateHeaders, MultipleCookies) {
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

TEST(CopyAndValidateTrailers, SimplestValidList) {
  // Verify that the simplest trailers are valid: just a final byte offset that
  // gets parsed successfully.
  auto trailers = FromList({{kFinalOffsetHeaderKey, "1234"}});
  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_TRUE(SpdyUtils::CopyAndValidateTrailers(*trailers, &final_byte_offset,
                                                 &block));
  EXPECT_EQ(1234u, final_byte_offset);
}

TEST(CopyAndValidateTrailers, EmptyTrailerList) {
  // An empty trailer list will fail as required key kFinalOffsetHeaderKey is
  // not present.
  QuicHeaderList trailers;
  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_FALSE(
      SpdyUtils::CopyAndValidateTrailers(trailers, &final_byte_offset, &block));
}

TEST(CopyAndValidateTrailers, FinalByteOffsetNotPresent) {
  // Validation fails if required kFinalOffsetHeaderKey is not present, even if
  // the rest of the header block is valid.
  auto trailers = FromList({{"key", "value"}});
  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_FALSE(SpdyUtils::CopyAndValidateTrailers(*trailers, &final_byte_offset,
                                                  &block));
}

TEST(CopyAndValidateTrailers, EmptyName) {
  // Trailer validation will fail with an empty header key, in an otherwise
  // valid block of trailers.
  auto trailers = FromList({{"", "value"}, {kFinalOffsetHeaderKey, "1234"}});
  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_FALSE(SpdyUtils::CopyAndValidateTrailers(*trailers, &final_byte_offset,
                                                  &block));
}

TEST(CopyAndValidateTrailers, PseudoHeaderInTrailers) {
  // Pseudo headers are illegal in trailers.
  auto trailers =
      FromList({{":pseudo_key", "value"}, {kFinalOffsetHeaderKey, "1234"}});
  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_FALSE(SpdyUtils::CopyAndValidateTrailers(*trailers, &final_byte_offset,
                                                  &block));
}

TEST(CopyAndValidateTrailers, DuplicateTrailers) {
  // Duplicate trailers are allowed, and their values are concatenated into a
  // single string delimted with '\0'. Some of the duplicate headers
  // deliberately have an empty value.
  FLAGS_quic_reloadable_flag_quic_handle_duplicate_trailers = true;
  auto trailers = FromList({{"key", "value0"},
                            {"key", "value1"},
                            {"key", ""},
                            {"key", ""},
                            {"key", "value2"},
                            {"key", ""},
                            {kFinalOffsetHeaderKey, "1234"},
                            {"other_key", "value"},
                            {"key", "non_contiguous_duplicate"}});
  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_TRUE(SpdyUtils::CopyAndValidateTrailers(*trailers, &final_byte_offset,
                                                 &block));
  EXPECT_THAT(
      block,
      UnorderedElementsAre(
          Pair("key",
               QuicStringPiece(
                   "value0\0value1\0\0\0value2\0\0non_contiguous_duplicate",
                   48)),
          Pair("other_key", "value")));
}

TEST(CopyAndValidateTrailers, DuplicateCookies) {
  // Duplicate cookie headers in trailers should be concatenated into a single
  //  "; " delimted string.
  FLAGS_quic_reloadable_flag_quic_handle_duplicate_trailers = true;
  auto headers = FromList({{"cookie", " part 1"},
                           {"cookie", "part 2 "},
                           {"cookie", "part3"},
                           {"key", "value"},
                           {kFinalOffsetHeaderKey, "1234"},
                           {"cookie", " non_contiguous_cookie!"}});

  size_t final_byte_offset = 0;
  SpdyHeaderBlock block;
  EXPECT_TRUE(
      SpdyUtils::CopyAndValidateTrailers(*headers, &final_byte_offset, &block));
  EXPECT_THAT(
      block,
      UnorderedElementsAre(
          Pair("cookie", " part 1; part 2 ; part3;  non_contiguous_cookie!"),
          Pair("key", "value")));
}

TEST(GetUrlFromHeaderBlock, Basic) {
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

TEST(GetHostNameFromHeaderBlock, NormalUsage) {
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

TEST(PopulateHeaderBlockFromUrl, NormalUsage) {
  string url = "https://www.google.com/index.html";
  SpdyHeaderBlock headers;
  EXPECT_TRUE(SpdyUtils::PopulateHeaderBlockFromUrl(url, &headers));
  EXPECT_EQ("https", headers[":scheme"].as_string());
  EXPECT_EQ("www.google.com", headers[":authority"].as_string());
  EXPECT_EQ("/index.html", headers[":path"].as_string());
}

TEST(PopulateHeaderBlockFromUrl, UrlWithNoPath) {
  string url = "https://www.google.com";
  SpdyHeaderBlock headers;
  EXPECT_TRUE(SpdyUtils::PopulateHeaderBlockFromUrl(url, &headers));
  EXPECT_EQ("https", headers[":scheme"].as_string());
  EXPECT_EQ("www.google.com", headers[":authority"].as_string());
  EXPECT_EQ("/", headers[":path"].as_string());
}

TEST(PopulateHeaderBlockFromUrl, Failure) {
  SpdyHeaderBlock headers;
  EXPECT_FALSE(SpdyUtils::PopulateHeaderBlockFromUrl("/", &headers));
  EXPECT_FALSE(SpdyUtils::PopulateHeaderBlockFromUrl("/index.html", &headers));
  EXPECT_FALSE(
      SpdyUtils::PopulateHeaderBlockFromUrl("www.google.com/", &headers));
}

}  // namespace test
}  // namespace net
