// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/files/file_path.h"
#include "base/memory/singleton.h"
#include "base/path_service.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "net/spdy/spdy_framer.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::ContainsKey;
using base::IntToString;
using base::StringPiece;
using net::SpdyHeaderBlock;
using std::string;

namespace net {
namespace test {

namespace {
typedef QuicHttpResponseCache::Response Response;
typedef QuicHttpResponseCache::ServerPushInfo ServerPushInfo;
};  // namespace

class QuicHttpResponseCacheTest : public ::testing::Test {
 protected:
  void CreateRequest(string host, string path, SpdyHeaderBlock* headers) {
    (*headers)[":method"] = "GET";
    (*headers)[":path"] = path;
    (*headers)[":authority"] = host;
    (*headers)[":scheme"] = "https";
  }

  string CacheDirectory() {
    base::FilePath path;
    PathService::Get(base::DIR_SOURCE_ROOT, &path);
    path = path.AppendASCII("net").AppendASCII("data").AppendASCII(
        "quic_http_response_cache_data");
    // The file path is known to be an ascii string.
    return path.MaybeAsASCII();
  }

  QuicHttpResponseCache cache_;
};

TEST_F(QuicHttpResponseCacheTest, GetResponseNoMatch) {
  const QuicHttpResponseCache::Response* response =
      cache_.GetResponse("mail.google.com", "/index.html");
  ASSERT_FALSE(response);
}

TEST_F(QuicHttpResponseCacheTest, AddSimpleResponseGetResponse) {
  string response_body("hello response");
  cache_.AddSimpleResponse("www.google.com", "/", 200, response_body);

  SpdyHeaderBlock request_headers;
  CreateRequest("www.google.com", "/", &request_headers);
  const QuicHttpResponseCache::Response* response =
      cache_.GetResponse("www.google.com", "/");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
  EXPECT_EQ(response_body.size(), response->body().length());
}

TEST_F(QuicHttpResponseCacheTest, AddResponse) {
  const string kRequestHost = "www.foo.com";
  const string kRequestPath = "/";
  const string kResponseBody("hello response");

  SpdyHeaderBlock response_headers;
  response_headers[":version"] = "HTTP/1.1";
  response_headers[":status"] = "200";
  response_headers["content-length"] = IntToString(kResponseBody.size());

  SpdyHeaderBlock response_trailers;
  response_trailers["key-1"] = "value-1";
  response_trailers["key-2"] = "value-2";
  response_trailers["key-3"] = "value-3";

  cache_.AddResponse(kRequestHost, "/", response_headers.Clone(), kResponseBody,
                     response_trailers.Clone());

  const QuicHttpResponseCache::Response* response =
      cache_.GetResponse(kRequestHost, kRequestPath);
  EXPECT_EQ(response->headers(), response_headers);
  EXPECT_EQ(response->body(), kResponseBody);
  EXPECT_EQ(response->trailers(), response_trailers);
}

TEST_F(QuicHttpResponseCacheTest, ReadsCacheDir) {
  cache_.InitializeFromDirectory(CacheDirectory());
  const QuicHttpResponseCache::Response* response =
      cache_.GetResponse("www.example.com", "/index.html");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
  // Connection headers are not valid in HTTP/2.
  EXPECT_FALSE(ContainsKey(response->headers(), "connection"));
  EXPECT_LT(0U, response->body().length());
}

TEST_F(QuicHttpResponseCacheTest, ReadsCacheDirWithServerPushResource) {
  cache_.InitializeFromDirectory(CacheDirectory() + "_with_push");
  std::list<ServerPushInfo> resources =
      cache_.GetServerPushResources("www.example.com/");
  ASSERT_EQ(1UL, resources.size());
}

TEST_F(QuicHttpResponseCacheTest, ReadsCacheDirWithServerPushResources) {
  cache_.InitializeFromDirectory(CacheDirectory() + "_with_push");
  std::list<ServerPushInfo> resources =
      cache_.GetServerPushResources("www.example.com/index2.html");
  ASSERT_EQ(2UL, resources.size());
}

TEST_F(QuicHttpResponseCacheTest, UsesOriginalUrl) {
  cache_.InitializeFromDirectory(CacheDirectory());
  const QuicHttpResponseCache::Response* response =
      cache_.GetResponse("www.example.com", "/site_map.html");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
  // Connection headers are not valid in HTTP/2.
  EXPECT_FALSE(ContainsKey(response->headers(), "connection"));
  EXPECT_LT(0U, response->body().length());
}

TEST_F(QuicHttpResponseCacheTest, DefaultResponse) {
  // Verify GetResponse returns nullptr when no default is set.
  const QuicHttpResponseCache::Response* response =
      cache_.GetResponse("www.google.com", "/");
  ASSERT_FALSE(response);

  // Add a default response.
  SpdyHeaderBlock response_headers;
  response_headers[":version"] = "HTTP/1.1";
  response_headers[":status"] = "200";
  response_headers["content-length"] = "0";
  QuicHttpResponseCache::Response* default_response =
      new QuicHttpResponseCache::Response;
  default_response->set_headers(std::move(response_headers));
  cache_.AddDefaultResponse(default_response);

  // Now we should get the default response for the original request.
  response = cache_.GetResponse("www.google.com", "/");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);

  // Now add a set response for / and make sure it is returned
  cache_.AddSimpleResponse("www.google.com", "/", 302, "");
  response = cache_.GetResponse("www.google.com", "/");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("302", response->headers().find(":status")->second);

  // We should get the default response for other requests.
  response = cache_.GetResponse("www.google.com", "/asd");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
}

TEST_F(QuicHttpResponseCacheTest, AddSimpleResponseWithServerPushResources) {
  string request_host = "www.foo.com";
  string response_body("hello response");
  const size_t kNumResources = 5;
  int NumResources = 5;
  std::list<QuicHttpResponseCache::ServerPushInfo> push_resources;
  string scheme = "http";
  for (int i = 0; i < NumResources; ++i) {
    string path = "/server_push_src" + base::IntToString(i);
    string url = scheme + "://" + request_host + path;
    GURL resource_url(url);
    string body = "This is server push response body for " + path;
    SpdyHeaderBlock response_headers;
    response_headers[":version"] = "HTTP/1.1";
    response_headers[":status"] = "200";
    response_headers["content-length"] = base::UintToString(body.size());
    push_resources.push_back(
        ServerPushInfo(resource_url, response_headers.Clone(), i, body));
  }

  cache_.AddSimpleResponseWithServerPushResources(
      request_host, "/", 200, response_body, push_resources);
  string request_url = request_host + "/";
  std::list<ServerPushInfo> resources =
      cache_.GetServerPushResources(request_url);
  ASSERT_EQ(kNumResources, resources.size());
  for (const auto& push_resource : push_resources) {
    ServerPushInfo resource = resources.front();
    EXPECT_EQ(resource.request_url.spec(), push_resource.request_url.spec());
    EXPECT_EQ(resource.priority, push_resource.priority);
    resources.pop_front();
  }
}

TEST_F(QuicHttpResponseCacheTest, GetServerPushResourcesAndPushResponses) {
  string request_host = "www.foo.com";
  string response_body("hello response");
  const size_t kNumResources = 4;
  int NumResources = 4;
  string scheme = "http";
  string push_response_status[kNumResources] = {"200", "200", "301", "404"};
  std::list<QuicHttpResponseCache::ServerPushInfo> push_resources;
  for (int i = 0; i < NumResources; ++i) {
    string path = "/server_push_src" + base::IntToString(i);
    string url = scheme + "://" + request_host + path;
    GURL resource_url(url);
    string body = "This is server push response body for " + path;
    SpdyHeaderBlock response_headers;
    response_headers[":version"] = "HTTP/1.1";
    response_headers[":status"] = push_response_status[i];
    response_headers["content-length"] = base::UintToString(body.size());
    push_resources.push_back(
        ServerPushInfo(resource_url, response_headers.Clone(), i, body));
  }
  cache_.AddSimpleResponseWithServerPushResources(
      request_host, "/", 200, response_body, push_resources);
  string request_url = request_host + "/";
  std::list<ServerPushInfo> resources =
      cache_.GetServerPushResources(request_url);
  ASSERT_EQ(kNumResources, resources.size());
  int i = 0;
  for (const auto& push_resource : push_resources) {
    GURL url = resources.front().request_url;
    string host = url.host();
    string path = url.path();
    const QuicHttpResponseCache::Response* response =
        cache_.GetResponse(host, path);
    ASSERT_TRUE(response);
    ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
    EXPECT_EQ(push_response_status[i++],
              response->headers().find(":status")->second);
    EXPECT_EQ(push_resource.body, response->body());
    resources.pop_front();
  }
}

}  // namespace test
}  // namespace net
