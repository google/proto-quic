// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/spdy_balsa_utils.h"

#include "base/strings/string_piece.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using testing::ElementsAre;

namespace net {
namespace test {
namespace {

TEST(SpdyBalsaUtilsTest, RequestHeadersToSpdyHeaders) {
  BalsaHeaders request_headers;
  request_headers.SetRequestFirstlineFromStringPieces(
      "GET", "https://www.google.com/foo", "HTTP/1.1");
  SpdyHeaderBlock spdy_headers =
      SpdyBalsaUtils::RequestHeadersToSpdyHeaders(request_headers);

  SpdyHeaderBlock expected_headers;
  expected_headers[":authority"] = "www.google.com";
  expected_headers[":path"] = "/foo";
  expected_headers[":scheme"] = "https";
  expected_headers[":method"] = "GET";

  EXPECT_EQ(expected_headers, spdy_headers);
}

TEST(SpdyBalsaUtilsTest, ResponseHeadersToSpdyHeaders) {
  BalsaHeaders response_headers;
  response_headers.SetResponseFirstlineFromStringPieces("HTTP/1.1", "200",
                                                        "OK");
  SpdyHeaderBlock spdy_headers =
      SpdyBalsaUtils::ResponseHeadersToSpdyHeaders(response_headers);

  SpdyHeaderBlock expected_headers;
  expected_headers[":status"] = "200";

  EXPECT_EQ(expected_headers, spdy_headers);
}

TEST(SpdyBalsaUtilsTest, SpdyHeadersToRequestHeaders) {
  // Test :authority header.
  SpdyHeaderBlock spdy_headers;
  spdy_headers[":authority"] = "www.google.com";
  spdy_headers[":path"] = "/foo";
  spdy_headers[":scheme"] = "https";
  spdy_headers[":method"] = "GET";
  spdy_headers["foo"] = StringPiece("multi\0valued\0header", 19);
  spdy_headers["bar"] = "";

  BalsaHeaders request_headers;
  SpdyBalsaUtils::SpdyHeadersToRequestHeaders(spdy_headers, &request_headers);
  EXPECT_EQ("GET", request_headers.request_method());
  EXPECT_EQ("HTTP/1.1", request_headers.request_version());
  EXPECT_EQ("/foo", request_headers.request_uri());
  EXPECT_EQ("www.google.com", request_headers.GetHeader("host"));
  EXPECT_TRUE(request_headers.HasHeader("bar"));
  EXPECT_EQ("", request_headers.GetHeader("bar"));
  std::vector<StringPiece> pieces;
  request_headers.GetAllOfHeader("foo", &pieces);
  EXPECT_THAT(pieces, ElementsAre("multi", "valued", "header"));

  // Test :host header (and no GET).
  SpdyHeaderBlock spdy_headers1;
  spdy_headers1[":host"] = "www.google.com";
  spdy_headers1[":path"] = "/foo";
  spdy_headers1[":scheme"] = "http";

  BalsaHeaders request_headers1;
  SpdyBalsaUtils::SpdyHeadersToRequestHeaders(spdy_headers1, &request_headers1);
  EXPECT_EQ("GET", request_headers1.request_method());
  EXPECT_EQ("HTTP/1.1", request_headers1.request_version());
  EXPECT_EQ("/foo", request_headers1.request_uri());
  EXPECT_EQ("www.google.com", request_headers1.GetHeader("host"));
}

TEST(SpdyBalsaUtilsTest, SpdyHeadersToResponseHeaders) {
  SpdyHeaderBlock spdy_headers;
  spdy_headers[":status"] = "200";
  spdy_headers["foo"] = StringPiece("multi\0valued\0header", 19);
  spdy_headers["bar"] = "";

  BalsaHeaders response_headers;
  SpdyBalsaUtils::SpdyHeadersToResponseHeaders(spdy_headers, &response_headers);
  EXPECT_EQ("200", response_headers.response_code());
  EXPECT_TRUE(response_headers.HasHeader("bar"));
  EXPECT_EQ("", response_headers.GetHeader("bar"));
  std::vector<StringPiece> pieces;
  response_headers.GetAllOfHeader("foo", &pieces);
  EXPECT_THAT(pieces, ElementsAre("multi", "valued", "header"));
}

}  // namespace
}  // namespace test
}  // namespace net
