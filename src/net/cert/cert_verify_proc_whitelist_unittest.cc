// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_whitelist.h"

#include "base/memory/ref_counted.h"
#include "net/cert/x509_certificate.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

namespace test1 {
#include "net/cert/cert_verify_proc_whitelist_unittest1-inc.cc"
}  // namespace test

TEST(CertVerifyProcWhitelistTest, HandlesWosignCerts) {
  // The domain must be in the whitelist from
  // //net/data/ssl/wosign/wosign_domains.gperf
  const char kWhitelistedDomain[] = "005.tv";
  const char kNonWhitelistedDomain[] = "006.tv";

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wosign_before_oct_21.pem");
  ASSERT_TRUE(cert);

  HashValueVector public_key_hashes;
  public_key_hashes.emplace_back(SHA256HashValue{
      {0x15, 0x28, 0x39, 0x7d, 0xa2, 0x12, 0x89, 0x0a, 0x83, 0x0b, 0x0b,
       0x95, 0xa5, 0x99, 0x68, 0xce, 0xf2, 0x34, 0x77, 0x37, 0x79, 0xdf,
       0x51, 0x81, 0xcf, 0x10, 0xfa, 0x64, 0x75, 0x34, 0xbb, 0x65}});

  // Domains on the whitelist are allowed, as long as their certificates were
  // pre-existing before Oct 21, 2016.
  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes,
                                           kWhitelistedDomain));
  // Domains not on the whitelist are not allowed, regardless of the validity
  // period of the certificate.
  EXPECT_TRUE(IsNonWhitelistedCertificate(*cert, public_key_hashes,
                                          kNonWhitelistedDomain));

  cert = ImportCertFromFile(GetTestCertsDirectory(), "wosign_after_oct_21.pem");
  ASSERT_TRUE(cert);

  // No new certificates (after Oct 21, 2016) are all allowed, regardless
  // of the domain.
  EXPECT_TRUE(IsNonWhitelistedCertificate(*cert, public_key_hashes,
                                          kWhitelistedDomain));
  EXPECT_TRUE(IsNonWhitelistedCertificate(*cert, public_key_hashes,
                                          kNonWhitelistedDomain));

  // Certificates that aren't issued by WoSign are allowed, regardless of
  // domain.
  public_key_hashes[0].data()[0] = 0x14;
  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes,
                                           kWhitelistedDomain));
  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes,
                                           kNonWhitelistedDomain));
}

TEST(CertVerifyProcWhitelistTest, IsWhitelistedHost) {
  const unsigned char* graph = test1::kDafsa;
  size_t graph_size = arraysize(test1::kDafsa);

  // Test malformed inputs.
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, ""));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "."));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, ".."));

  // Make sure that TLDs aren't accepted just because a subdomain is.
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "com"));

  // Test various forms of domain names that GURL will accept for entries in
  // the graph.
  EXPECT_TRUE(IsWhitelistedHost(graph, graph_size, "example.com"));
  EXPECT_TRUE(IsWhitelistedHost(graph, graph_size, "subdomain.example.com"));
  EXPECT_TRUE(IsWhitelistedHost(graph, graph_size, ".subdomain.example.com"));
  EXPECT_TRUE(IsWhitelistedHost(graph, graph_size, "example.com."));
  EXPECT_TRUE(IsWhitelistedHost(graph, graph_size, ".example.com."));
  EXPECT_TRUE(IsWhitelistedHost(graph, graph_size, "www.example.bar.jp"));

  // Test various prefix/suffices of entries in the graph, but that aren't
  // themselves domain matches.
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "anotherexample.com"));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "bar.jp"));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "example.bar.jp.junk"));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "foo.example.bar.jp.junk"));

  // Test various forms of domain names that GURL will accept for entries not
  // in the graph.
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "domain.com"));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "example..com"));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "www.co.uk"));
  EXPECT_FALSE(IsWhitelistedHost(graph, graph_size, "www..co.uk"));
}

}  // namespace

}  // namespace net
