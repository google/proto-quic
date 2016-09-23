// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/http_response.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test_server {

TEST(HttpResponseTest, GenerateResponse) {
  BasicHttpResponse response;
  response.set_code(HTTP_OK);
  response.set_content("Sample content - Hello world!");
  response.set_content_type("text/plain");
  response.AddCustomHeader("Simple-Header", "Simple value.");

  std::string kExpectedResponseString =
      "HTTP/1.1 200 OK\r\n"
      "Connection: close\r\n"
      "Content-Length: 29\r\n"
      "Content-Type: text/plain\r\n"
      "Simple-Header: Simple value.\r\n\r\n"
      "Sample content - Hello world!";

  EXPECT_EQ(kExpectedResponseString, response.ToResponseString());
}

}  // namespace test_server
}  // namespace net
