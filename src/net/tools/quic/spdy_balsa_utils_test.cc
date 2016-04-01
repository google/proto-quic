// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/spdy_balsa_utils.h"

#include "net/spdy/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

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

  BalsaHeaders request_headers;
  SpdyBalsaUtils::SpdyHeadersToRequestHeaders(spdy_headers, &request_headers);
  EXPECT_EQ("GET", request_headers.request_method());
  EXPECT_EQ("HTTP/1.1", request_headers.request_version());
  EXPECT_EQ("/foo", request_headers.request_uri());
  EXPECT_EQ("www.google.com", request_headers.GetHeader("host"));

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

  BalsaHeaders response_headers;
  SpdyBalsaUtils::SpdyHeadersToResponseHeaders(spdy_headers, &response_headers);
  EXPECT_EQ("200", response_headers.response_code());
}

}  // namespace
}  // namespace test
}  // namespace net
