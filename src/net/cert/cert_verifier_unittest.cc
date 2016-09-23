// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verifier.h"

#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "net/cert/x509_certificate.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(CertVerifierTest, RequestParamsComparators) {
  const scoped_refptr<X509Certificate> ok_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(ok_cert.get());

  const scoped_refptr<X509Certificate> expired_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  ASSERT_TRUE(expired_cert.get());

  const scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  ASSERT_TRUE(root_cert.get());

  // Create a certificate that contains both a leaf and an
  // intermediate/root.
  X509Certificate::OSCertHandles chain;
  chain.push_back(root_cert->os_cert_handle());
  const scoped_refptr<X509Certificate> combined_cert =
      X509Certificate::CreateFromHandle(ok_cert->os_cert_handle(), chain);
  ASSERT_TRUE(combined_cert.get());

  const CertificateList empty_list;
  CertificateList test_list;
  test_list.push_back(ok_cert);

  struct {
    // Keys to test
    CertVerifier::RequestParams key1;
    CertVerifier::RequestParams key2;

    // Whether or not |key1| and |key2| are expected to be equal.
    bool equal;
  } tests[] = {
      {
          // Test for basic equivalence.
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          true,
      },
      {
          // Test that different certificates but with the same CA and for
          // the same host are different validation keys.
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          CertVerifier::RequestParams(expired_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          false,
      },
      {
          // Test that the same EE certificate for the same host, but with
          // different chains are different validation keys.
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          CertVerifier::RequestParams(combined_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          false,
      },
      {
          // The same certificate, with the same chain, but for different
          // hosts are different validation keys.
          CertVerifier::RequestParams(ok_cert, "www1.example.test", 0,
                                      std::string(), empty_list),
          CertVerifier::RequestParams(ok_cert, "www2.example.test", 0,
                                      std::string(), empty_list),
          false,
      },
      {
          // The same certificate, chain, and host, but with different flags
          // are different validation keys.
          CertVerifier::RequestParams(ok_cert, "www.example.test",
                                      CertVerifier::VERIFY_EV_CERT,
                                      std::string(), empty_list),
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          false,
      },
      {
          // Different additional_trust_anchors.
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), test_list),
          false,
      },
      {
          // Different OCSP responses.
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      "ocsp response", empty_list),
          CertVerifier::RequestParams(ok_cert, "www.example.test", 0,
                                      std::string(), empty_list),
          false,
      },
  };
  for (size_t i = 0; i < arraysize(tests); ++i) {
    SCOPED_TRACE(i);

    const CertVerifier::RequestParams& key1 = tests[i].key1;
    const CertVerifier::RequestParams& key2 = tests[i].key2;

    // Ensure that the keys are equivalent to themselves.
    EXPECT_FALSE(key1 < key1);
    EXPECT_FALSE(key2 < key2);

    if (tests[i].equal) {
      EXPECT_TRUE(!(key1 < key2) && !(key2 < key1));
    } else {
      EXPECT_TRUE((key1 < key2) || (key2 < key1));
    }
  }
}

}  // namespace net
