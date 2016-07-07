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
#include "base/strings/stringprintf.h"
#include "net/spdy/spdy_framer.h"
#include "net/tools/balsa/balsa_headers.h"
#include "net/tools/quic/quic_in_memory_cache.h"
#include "net/tools/quic/test_tools/quic_in_memory_cache_peer.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::IntToString;
using base::StringPiece;
using net::SpdyHeaderBlock;
using std::list;
using std::string;

namespace net {
namespace test {

namespace {
typedef QuicInMemoryCache::Response Response;
typedef QuicInMemoryCache::ServerPushInfo ServerPushInfo;
};  // namespace

class QuicInMemoryCacheTest : public ::testing::Test {
 protected:
  QuicInMemoryCacheTest() { QuicInMemoryCachePeer::ResetForTests(); }

  ~QuicInMemoryCacheTest() override { QuicInMemoryCachePeer::ResetForTests(); }

  void CreateRequest(string host, string path, BalsaHeaders* headers) {
    headers->SetRequestFirstlineFromStringPieces("GET", path, "HTTP/1.1");
    headers->ReplaceOrAppendHeader("host", host);
  }

  string CacheDirectory() {
    base::FilePath path;
    PathService::Get(base::DIR_SOURCE_ROOT, &path);
    path = path.AppendASCII("net").AppendASCII("data").AppendASCII(
        "quic_in_memory_cache_data");
    // The file path is known to be an ascii string.
    return path.MaybeAsASCII();
  }
};

TEST_F(QuicInMemoryCacheTest, GetResponseNoMatch) {
  const QuicInMemoryCache::Response* response =
      QuicInMemoryCache::GetInstance()->GetResponse("mail.google.com",
                                                    "/index.html");
  ASSERT_FALSE(response);
}

TEST_F(QuicInMemoryCacheTest, AddSimpleResponseGetResponse) {
  string response_body("hello response");
  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  cache->AddSimpleResponse("www.google.com", "/", 200, response_body);

  BalsaHeaders request_headers;
  CreateRequest("www.google.com", "/", &request_headers);
  const QuicInMemoryCache::Response* response =
      cache->GetResponse("www.google.com", "/");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
  EXPECT_EQ(response_body.size(), response->body().length());
}

TEST_F(QuicInMemoryCacheTest, AddResponse) {
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

  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  cache->AddResponse(kRequestHost, "/", response_headers.Clone(), kResponseBody,
                     response_trailers.Clone());

  const QuicInMemoryCache::Response* response =
      cache->GetResponse(kRequestHost, kRequestPath);
  EXPECT_EQ(response->headers(), response_headers);
  EXPECT_EQ(response->body(), kResponseBody);
  EXPECT_EQ(response->trailers(), response_trailers);
}

TEST_F(QuicInMemoryCacheTest, ReadsCacheDir) {
  QuicInMemoryCache::GetInstance()->InitializeFromDirectory(CacheDirectory());
  const QuicInMemoryCache::Response* response =
      QuicInMemoryCache::GetInstance()->GetResponse("quic.test.url",
                                                    "/index.html");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
  ASSERT_TRUE(ContainsKey(response->headers(), "connection"));
  EXPECT_EQ("close", response->headers().find("connection")->second);
  EXPECT_LT(0U, response->body().length());
}

TEST_F(QuicInMemoryCacheTest, ReadsCacheDirWithServerPushResource) {
  QuicInMemoryCache::GetInstance()->InitializeFromDirectory(CacheDirectory() +
                                                            "_with_push");
  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  list<ServerPushInfo> resources =
      cache->GetServerPushResources("quic.test.url/");
  ASSERT_EQ(1UL, resources.size());
}

TEST_F(QuicInMemoryCacheTest, ReadsCacheDirWithServerPushResources) {
  QuicInMemoryCache::GetInstance()->InitializeFromDirectory(CacheDirectory() +
                                                            "_with_push");
  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  list<ServerPushInfo> resources =
      cache->GetServerPushResources("quic.test.url/index2.html");
  ASSERT_EQ(2UL, resources.size());
}

TEST_F(QuicInMemoryCacheTest, UsesOriginalUrl) {
  QuicInMemoryCache::GetInstance()->InitializeFromDirectory(CacheDirectory());
  const QuicInMemoryCache::Response* response =
      QuicInMemoryCache::GetInstance()->GetResponse("quic.test.url",
                                                    "/index.html");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
  ASSERT_TRUE(ContainsKey(response->headers(), "connection"));
  EXPECT_EQ("close", response->headers().find("connection")->second);
  EXPECT_LT(0U, response->body().length());
}

TEST_F(QuicInMemoryCacheTest, DefaultResponse) {
  // Verify GetResponse returns nullptr when no default is set.
  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  const QuicInMemoryCache::Response* response =
      cache->GetResponse("www.google.com", "/");
  ASSERT_FALSE(response);

  // Add a default response.
  SpdyHeaderBlock response_headers;
  response_headers[":version"] = "HTTP/1.1";
  response_headers[":status"] = "200";
  response_headers["content-length"] = "0";
  QuicInMemoryCache::Response* default_response =
      new QuicInMemoryCache::Response;
  default_response->set_headers(std::move(response_headers));
  cache->AddDefaultResponse(default_response);

  // Now we should get the default response for the original request.
  response = cache->GetResponse("www.google.com", "/");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);

  // Now add a set response for / and make sure it is returned
  cache->AddSimpleResponse("www.google.com", "/", 302, "");
  response = cache->GetResponse("www.google.com", "/");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("302", response->headers().find(":status")->second);

  // We should get the default response for other requests.
  response = cache->GetResponse("www.google.com", "/asd");
  ASSERT_TRUE(response);
  ASSERT_TRUE(ContainsKey(response->headers(), ":status"));
  EXPECT_EQ("200", response->headers().find(":status")->second);
}

TEST_F(QuicInMemoryCacheTest, AddSimpleResponseWithServerPushResources) {
  string request_host = "www.foo.com";
  string response_body("hello response");
  const size_t kNumResources = 5;
  int NumResources = 5;
  list<QuicInMemoryCache::ServerPushInfo> push_resources;
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

  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  cache->AddSimpleResponseWithServerPushResources(
      request_host, "/", 200, response_body, push_resources);
  string request_url = request_host + "/";
  list<ServerPushInfo> resources = cache->GetServerPushResources(request_url);
  ASSERT_EQ(kNumResources, resources.size());
  for (const auto& push_resource : push_resources) {
    ServerPushInfo resource = resources.front();
    EXPECT_EQ(resource.request_url.spec(), push_resource.request_url.spec());
    EXPECT_EQ(resource.priority, push_resource.priority);
    resources.pop_front();
  }
}

TEST_F(QuicInMemoryCacheTest, GetServerPushResourcesAndPushResponses) {
  string request_host = "www.foo.com";
  string response_body("hello response");
  const size_t kNumResources = 4;
  int NumResources = 4;
  string scheme = "http";
  string push_response_status[kNumResources] = {"200", "200", "301", "404"};
  list<QuicInMemoryCache::ServerPushInfo> push_resources;
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
  QuicInMemoryCache* cache = QuicInMemoryCache::GetInstance();
  cache->AddSimpleResponseWithServerPushResources(
      request_host, "/", 200, response_body, push_resources);
  string request_url = request_host + "/";
  list<ServerPushInfo> resources = cache->GetServerPushResources(request_url);
  ASSERT_EQ(kNumResources, resources.size());
  int i = 0;
  for (const auto& push_resource : push_resources) {
    GURL url = resources.front().request_url;
    string host = url.host();
    string path = url.path();
    const QuicInMemoryCache::Response* response =
        cache->GetResponse(host, path);
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
