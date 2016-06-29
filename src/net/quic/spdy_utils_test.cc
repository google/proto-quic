// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/quic/spdy_utils.h"

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "net/test/gtest_util.h"

using base::StringPiece;
using std::string;
using testing::UnorderedElementsAre;
using testing::Pair;

namespace net {
namespace test {

TEST(SpdyUtilsTest, SerializeAndParseHeaders) {
  // Creates a SpdyHeaderBlock with some key->value pairs, serializes it, then
  // parses the serialized output and verifies that the end result is the same
  // as the headers that the test started with.

  SpdyHeaderBlock input_headers;
  input_headers[":pseudo1"] = "pseudo value1";
  input_headers[":pseudo2"] = "pseudo value2";
  input_headers["key1"] = "value1";
  const int64_t kContentLength = 1234;
  input_headers["content-length"] = base::Int64ToString(kContentLength);
  input_headers["key2"] = "value2";

  // Serialize the header block.
  string serialized_headers =
      SpdyUtils::SerializeUncompressedHeaders(input_headers);

  // Take the serialized header block, and parse back into SpdyHeaderBlock.
  SpdyHeaderBlock output_headers;
  int64_t content_length = -1;
  ASSERT_TRUE(SpdyUtils::ParseHeaders(serialized_headers.data(),
                                      serialized_headers.size(),
                                      &content_length, &output_headers));

  // Should be back to the original headers.
  EXPECT_EQ(content_length, kContentLength);
  EXPECT_EQ(output_headers, input_headers);
}

TEST(SpdyUtilsTest, SerializeAndParseHeadersLargeContentLength) {
  // Creates a SpdyHeaderBlock with some key->value pairs, serializes it, then
  // parses the serialized output and verifies that the end result is the same
  // as the headers that the test started with.

  SpdyHeaderBlock input_headers;
  input_headers[":pseudo1"] = "pseudo value1";
  input_headers[":pseudo2"] = "pseudo value2";
  input_headers["key1"] = "value1";
  const int64_t kContentLength = 12345678900;
  input_headers["content-length"] = base::Int64ToString(kContentLength);
  input_headers["key2"] = "value2";

  // Serialize the header block.
  string serialized_headers =
      SpdyUtils::SerializeUncompressedHeaders(input_headers);

  // Take the serialized header block, and parse back into SpdyHeaderBlock.
  SpdyHeaderBlock output_headers;
  int64_t content_length = -1;
  ASSERT_TRUE(SpdyUtils::ParseHeaders(serialized_headers.data(),
                                      serialized_headers.size(),
                                      &content_length, &output_headers));

  // Should be back to the original headers.
  EXPECT_EQ(content_length, kContentLength);
  EXPECT_EQ(output_headers, input_headers);
}

TEST(SpdyUtilsTest, SerializeAndParseValidTrailers) {
  // Creates a SpdyHeaderBlock with some valid Trailers key->value pairs,
  // serializes it, then parses the serialized output and verifies that the end
  // result is the same as the trailers that the test started with.
  SpdyHeaderBlock input_trailers;
  const size_t kFinalOffset = 5678;
  input_trailers[kFinalOffsetHeaderKey] = base::IntToString(kFinalOffset);
  input_trailers["key1"] = "value1";
  input_trailers["key2"] = "value2";

  // Serialize the trailers.
  string serialized_trailers =
      SpdyUtils::SerializeUncompressedHeaders(input_trailers);

  // Take the serialized trailers, and parse back into a SpdyHeaderBlock.
  SpdyHeaderBlock output_trailers;
  size_t final_byte_offset = 0;
  EXPECT_TRUE(SpdyUtils::ParseTrailers(serialized_trailers.data(),
                                       serialized_trailers.size(),
                                       &final_byte_offset, &output_trailers));

  // Should be back to the original trailers, without the final offset header.
  EXPECT_EQ(final_byte_offset, kFinalOffset);
  input_trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(output_trailers, input_trailers);
}

TEST(SpdyUtilsTest, SerializeAndParseTrailersWithoutFinalOffset) {
  // Verifies that parsing fails if Trailers are missing a final offset header.

  SpdyHeaderBlock input_trailers;
  input_trailers["key1"] = "value1";
  input_trailers["key2"] = "value2";

  // Serialize the trailers.
  string serialized_trailers =
      SpdyUtils::SerializeUncompressedHeaders(input_trailers);

  // Parsing the serialized trailers fails because of the missing final offset.
  SpdyHeaderBlock output_trailers;
  size_t final_byte_offset = 0;
  EXPECT_FALSE(SpdyUtils::ParseTrailers(serialized_trailers.data(),
                                        serialized_trailers.size(),
                                        &final_byte_offset, &output_trailers));
  EXPECT_EQ(final_byte_offset, 0u);
}

TEST(SpdyUtilsTest, SerializeAndParseTrailersWithPseudoHeaders) {
  // Verifies that parsing fails if Trailers include pseudo-headers.

  SpdyHeaderBlock input_trailers;
  input_trailers[kFinalOffsetHeaderKey] = "12345";
  input_trailers[":disallowed-pseudo-header"] = "pseudo value";
  input_trailers["key1"] = "value1";
  input_trailers["key2"] = "value2";

  // Serialize the trailers.
  string serialized_trailers =
      SpdyUtils::SerializeUncompressedHeaders(input_trailers);

  // Parsing the serialized trailers fails because of the extra pseudo header.
  SpdyHeaderBlock output_trailers;
  size_t final_byte_offset = 0;
  EXPECT_FALSE(SpdyUtils::ParseTrailers(serialized_trailers.data(),
                                        serialized_trailers.size(),
                                        &final_byte_offset, &output_trailers));
}
static std::unique_ptr<QuicHeaderList> FromList(
    const QuicHeaderList::ListType& src) {
  std::unique_ptr<QuicHeaderList> headers(new QuicHeaderList);
  headers->OnHeaderBlockStart();
  for (const auto& p : src) {
    headers->OnHeader(p.first, p.second);
  }
  headers->OnHeaderBlockEnd(0);
  return headers;
}

TEST(SpdyUtilsTest, CopyAndValidateHeaders) {
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
  EXPECT_THAT(block, UnorderedElementsAre(
                         Pair("cookie", " part 1; part 2 ; part3;  fin!"),
                         Pair("passed-through", StringPiece("foo\0baz", 7)),
                         Pair("joined", StringPiece("value 1\0value 2", 15)),
                         Pair("empty", ""),
                         Pair("empty-joined", StringPiece("\0foo\0\0", 6))));
  EXPECT_EQ(-1, content_length);
}

TEST(SpdyUtilsTest, CopyAndValidateHeadersEmptyName) {
  auto headers = FromList({{"foo", "foovalue"}, {"", "barvalue"}, {"baz", ""}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_FALSE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
}

TEST(SpdyUtilsTest, CopyAndValidateHeadersMultipleContentLengths) {
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
                         Pair("content-length", StringPiece("9"
                                                            "\0"
                                                            "9",
                                                            3)),
                         Pair("baz", "")));
  EXPECT_EQ(9, content_length);
}

TEST(SpdyUtilsTest, CopyAndValidateHeadersInconsistentContentLengths) {
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

TEST(SpdyUtilsTest, CopyAndValidateHeadersLargeContentLength) {
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
                         Pair("content-length", StringPiece("9000000000")),
                         Pair("baz", "")));
  EXPECT_EQ(9000000000, content_length);
}

TEST(SpdyUtilsTest, CopyAndValidateHeadersMultipleValues) {
  auto headers = FromList({{"foo", "foovalue"},
                           {"bar", "barvalue"},
                           {"baz", ""},
                           {"foo", "boo"},
                           {"baz", "buzz"}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(
      block, UnorderedElementsAre(Pair("foo", StringPiece("foovalue\0boo", 12)),
                                  Pair("bar", "barvalue"),
                                  Pair("baz", StringPiece("\0buzz", 5))));
  EXPECT_EQ(-1, content_length);
}

TEST(SpdyUtilsTest, CopyAndValidateHeadersMoreThanTwoValues) {
  auto headers = FromList({{"set-cookie", "value1"},
                           {"set-cookie", "value2"},
                           {"set-cookie", "value3"}});
  int64_t content_length = -1;
  SpdyHeaderBlock block;
  ASSERT_TRUE(
      SpdyUtils::CopyAndValidateHeaders(*headers, &content_length, &block));
  EXPECT_THAT(block,
              UnorderedElementsAre(Pair(
                  "set-cookie", StringPiece("value1\0value2\0value3", 20))));
  EXPECT_EQ(-1, content_length);
}

TEST(SpdyUtilsTest, CopyAndValidateHeadersCookie) {
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

TEST(SpdyUtilsTest, CopyAndValidateHeadersMultipleCookies) {
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

TEST(SpdyUtilsTest, GetUrlFromHeaderBlock) {
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

TEST(SpdyUtilsTest, GetHostNameFromHeaderBlock) {
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

TEST(SpdyUtilsTest, UrlIsValid) {
  SpdyHeaderBlock headers;
  EXPECT_FALSE(SpdyUtils::UrlIsValid(headers));
  headers[":scheme"] = "https";
  EXPECT_FALSE(SpdyUtils::UrlIsValid(headers));
  headers[":authority"] = "www.google.com";
  EXPECT_FALSE(SpdyUtils::UrlIsValid(headers));
  headers[":path"] = "/index.html";
  EXPECT_TRUE(SpdyUtils::UrlIsValid(headers));
}

}  // namespace test
}  // namespace net
