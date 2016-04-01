// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/quic/spdy_utils.h"

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "net/test/gtest_util.h"

using std::string;

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
  const int kContentLength = 1234;
  input_headers["content-length"] = base::IntToString(kContentLength);
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
