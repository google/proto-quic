// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_vary_data.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

typedef testing::Test HttpVaryDataTest;

struct TestTransaction {
  HttpRequestInfo request;
  scoped_refptr<HttpResponseHeaders> response;

  void Init(const std::string& request_headers,
            const std::string& response_headers) {
    std::string temp(response_headers);
    std::replace(temp.begin(), temp.end(), '\n', '\0');
    response = new HttpResponseHeaders(temp);

    request.extra_headers.Clear();
    request.extra_headers.AddHeadersFromString(request_headers);
  }
};

}  // namespace

TEST(HttpVaryDataTest, IsInvalid) {
  // All of these responses should result in an invalid vary data object.
  const char* const kTestResponses[] = {
    "HTTP/1.1 200 OK\n\n",
    "HTTP/1.1 200 OK\nVary: *\n\n",
    "HTTP/1.1 200 OK\nVary: cookie, *, bar\n\n",
    "HTTP/1.1 200 OK\nVary: cookie\nFoo: 1\nVary: *\n\n",
  };

  for (size_t i = 0; i < arraysize(kTestResponses); ++i) {
    TestTransaction t;
    t.Init(std::string(), kTestResponses[i]);

    HttpVaryData v;
    EXPECT_FALSE(v.is_valid());
    EXPECT_FALSE(v.Init(t.request, *t.response.get()));
    EXPECT_FALSE(v.is_valid());
  }
}

TEST(HttpVaryDataTest, MultipleInit) {
  HttpVaryData v;

  // Init to something valid.
  TestTransaction t1;
  t1.Init("Foo: 1\r\nbar: 23", "HTTP/1.1 200 OK\nVary: foo, bar\n\n");
  EXPECT_TRUE(v.Init(t1.request, *t1.response.get()));
  EXPECT_TRUE(v.is_valid());

  // Now overwrite by initializing to something invalid.
  TestTransaction t2;
  t2.Init("Foo: 1\r\nbar: 23", "HTTP/1.1 200 OK\nVary: *\n\n");
  EXPECT_FALSE(v.Init(t2.request, *t2.response.get()));
  EXPECT_FALSE(v.is_valid());
}

TEST(HttpVaryDataTest, DoesVary) {
  TestTransaction a;
  a.Init("Foo: 1", "HTTP/1.1 200 OK\nVary: foo\n\n");

  TestTransaction b;
  b.Init("Foo: 2", "HTTP/1.1 200 OK\nVary: foo\n\n");

  HttpVaryData v;
  EXPECT_TRUE(v.Init(a.request, *a.response.get()));

  EXPECT_FALSE(v.MatchesRequest(b.request, *b.response.get()));
}

TEST(HttpVaryDataTest, DoesVary2) {
  TestTransaction a;
  a.Init("Foo: 1\r\nbar: 23", "HTTP/1.1 200 OK\nVary: foo, bar\n\n");

  TestTransaction b;
  b.Init("Foo: 12\r\nbar: 3", "HTTP/1.1 200 OK\nVary: foo, bar\n\n");

  HttpVaryData v;
  EXPECT_TRUE(v.Init(a.request, *a.response.get()));

  EXPECT_FALSE(v.MatchesRequest(b.request, *b.response.get()));
}

TEST(HttpVaryDataTest, DoesntVary) {
  TestTransaction a;
  a.Init("Foo: 1", "HTTP/1.1 200 OK\nVary: foo\n\n");

  TestTransaction b;
  b.Init("Foo: 1", "HTTP/1.1 200 OK\nVary: foo\n\n");

  HttpVaryData v;
  EXPECT_TRUE(v.Init(a.request, *a.response.get()));

  EXPECT_TRUE(v.MatchesRequest(b.request, *b.response.get()));
}

TEST(HttpVaryDataTest, DoesntVary2) {
  TestTransaction a;
  a.Init("Foo: 1\r\nbAr: 2", "HTTP/1.1 200 OK\nVary: foo, bar\n\n");

  TestTransaction b;
  b.Init("Foo: 1\r\nbaR: 2", "HTTP/1.1 200 OK\nVary: foo\nVary: bar\n\n");

  HttpVaryData v;
  EXPECT_TRUE(v.Init(a.request, *a.response.get()));

  EXPECT_TRUE(v.MatchesRequest(b.request, *b.response.get()));
}

TEST(HttpVaryDataTest, DoesntVaryByCookieForRedirect) {
  TestTransaction a;
  a.Init("Cookie: 1", "HTTP/1.1 301 Moved\nLocation: x\n\n");

  HttpVaryData v;
  EXPECT_FALSE(v.Init(a.request, *a.response.get()));
}

}  // namespace net
