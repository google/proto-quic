// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/api/quic_url.h"

#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {
namespace {

TEST(QuicUrlTest, Basic) {
  // No scheme specified.
  string url_str = "www.example.com";
  QuicUrl url(url_str);
  EXPECT_FALSE(url.IsValid());

  // scheme is HTTP.
  url_str = "http://www.example.com";
  url = QuicUrl(url_str);
  EXPECT_TRUE(url.IsValid());
  EXPECT_EQ("http://www.example.com/", url.ToString());
  EXPECT_EQ("http", url.scheme());
  EXPECT_EQ("www.example.com", url.HostPort());
  EXPECT_EQ("/", url.PathParamsQuery());
  EXPECT_EQ(80u, url.port());

  // scheme is HTTPS.
  url_str = "https://www.example.com:12345/path/to/resource?a=1&campaign=2";
  url = QuicUrl(url_str);
  EXPECT_TRUE(url.IsValid());
  EXPECT_EQ("https://www.example.com:12345/path/to/resource?a=1&campaign=2",
            url.ToString());
  EXPECT_EQ("https", url.scheme());
  EXPECT_EQ("www.example.com:12345", url.HostPort());
  EXPECT_EQ("/path/to/resource?a=1&campaign=2", url.PathParamsQuery());
  EXPECT_EQ(12345u, url.port());

  // scheme is FTP.
  url_str = "ftp://www.example.com";
  url = QuicUrl(url_str);
  EXPECT_TRUE(url.IsValid());
  EXPECT_EQ("ftp://www.example.com/", url.ToString());
  EXPECT_EQ("ftp", url.scheme());
  EXPECT_EQ("www.example.com", url.HostPort());
  EXPECT_EQ("/", url.PathParamsQuery());
  EXPECT_EQ(21u, url.port());
}

TEST(QuicUrlTest, DefaultScheme) {
  // Default scheme to HTTP.
  string url_str = "www.example.com";
  QuicUrl url(url_str, "http");
  EXPECT_EQ("http://www.example.com/", url.ToString());
  EXPECT_EQ("http", url.scheme());

  // URL already has a scheme specified.
  url_str = "http://www.example.com";
  url = QuicUrl(url_str, "https");
  EXPECT_EQ("http://www.example.com/", url.ToString());
  EXPECT_EQ("http", url.scheme());

  // Default scheme to FTP.
  url_str = "www.example.com";
  url = QuicUrl(url_str, "ftp");
  EXPECT_EQ("ftp://www.example.com/", url.ToString());
  EXPECT_EQ("ftp", url.scheme());
}

TEST(QuicUrlTest, IsValid) {
  string url_str =
      "ftp://www.example.com:12345/path/to/resource?a=1&campaign=2";
  EXPECT_TRUE(QuicUrl(url_str).IsValid());

  // Invalid characters in host name.
  url_str = "https://www%.example.com:12345/path/to/resource?a=1&campaign=2";
  EXPECT_FALSE(QuicUrl(url_str).IsValid());

  // Invalid characters in scheme.
  url_str = "%http://www.example.com:12345/path/to/resource?a=1&campaign=2";
  EXPECT_FALSE(QuicUrl(url_str).IsValid());

  // Host name too long.
  string host(1024, 'a');
  url_str = "https://" + host;
  EXPECT_FALSE(QuicUrl(url_str).IsValid());

  // Invalid port number.
  url_str = "https://www..example.com:123456/path/to/resource?a=1&campaign=2";
  EXPECT_FALSE(QuicUrl(url_str).IsValid());
}

TEST(QuicUrlTest, HostPort) {
  string url_str = "http://www.example.com/";
  QuicUrl url(url_str);
  EXPECT_EQ("www.example.com", url.HostPort());
  EXPECT_EQ("www.example.com", url.host());
  EXPECT_EQ(80u, url.port());

  url_str = "http://www.example.com:80/";
  url = QuicUrl(url_str);
  EXPECT_EQ("www.example.com", url.HostPort());
  EXPECT_EQ("www.example.com", url.host());
  EXPECT_EQ(80u, url.port());

  url_str = "http://www.example.com:81/";
  url = QuicUrl(url_str);
  EXPECT_EQ("www.example.com:81", url.HostPort());
  EXPECT_EQ("www.example.com", url.host());
  EXPECT_EQ(81u, url.port());

  url_str = "https://192.168.1.1:443/";
  url = QuicUrl(url_str);
  EXPECT_EQ("192.168.1.1", url.HostPort());
  EXPECT_EQ("192.168.1.1", url.host());
  EXPECT_EQ(443u, url.port());

  url_str = "http://[2001::1]:80/";
  url = QuicUrl(url_str);
  EXPECT_EQ("[2001::1]", url.HostPort());
  EXPECT_EQ("2001::1", url.host());
  EXPECT_EQ(80u, url.port());

  url_str = "http://[2001::1]:81/";
  url = QuicUrl(url_str);
  EXPECT_EQ("[2001::1]:81", url.HostPort());
  EXPECT_EQ("2001::1", url.host());
  EXPECT_EQ(81u, url.port());
}

TEST(QuicUrlTest, PathParamsQuery) {
  string url_str =
      "https://www.example.com:12345/path/to/resource?a=1&campaign=2";
  QuicUrl url(url_str);
  EXPECT_EQ("/path/to/resource?a=1&campaign=2", url.PathParamsQuery());
  EXPECT_EQ("/path/to/resource", url.path());

  url_str = "https://www.example.com/?";
  url = QuicUrl(url_str);
  EXPECT_EQ("/?", url.PathParamsQuery());
  EXPECT_EQ("/", url.path());

  url_str = "https://www.example.com/";
  url = QuicUrl(url_str);
  EXPECT_EQ("/", url.PathParamsQuery());
  EXPECT_EQ("/", url.path());
}

}  // namespace
}  // namespace test
}  // namespace net
