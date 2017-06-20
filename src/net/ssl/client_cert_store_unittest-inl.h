// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_CLIENT_CERT_STORE_UNITTEST_INL_H_
#define NET_SSL_CLIENT_CERT_STORE_UNITTEST_INL_H_

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// "CN=B CA" - DER encoded DN of the issuer of client_1.pem
const unsigned char kAuthority1DN[] = {
    0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x04, 0x42, 0x20, 0x43, 0x41,
};

// "CN=E CA" - DER encoded DN of the issuer of client_2.pem
const unsigned char kAuthority2DN[] = {
    0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x04, 0x45, 0x20, 0x43, 0x41,
};

// "CN=C Root CA" - DER encoded DN of the issuer of client_1_ca.pem,
// client_2_ca.pem, and client_3_ca.pem.
const unsigned char kAuthorityRootDN[] = {
    0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x09, 0x43, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41,
};

}  // namespace

// Use a templated test to provide common testcases for all the platform
// implementations of ClientCertStore. These cases test the client cert
// filtering behavior.
//
// NOTE: If any test cases are added, removed, or renamed, the
// REGISTER_TYPED_TEST_CASE_P macro at the bottom of this file must be updated.
//
// The type T provided as the third argument to INSTANTIATE_TYPED_TEST_CASE_P by
// the platform implementation should implement this method:
// bool SelectClientCerts(const CertificateList& input_certs,
//                        const SSLCertRequestInfo& cert_request_info,
//                        ClientCertIdentityList* selected_identities);
template <typename T>
class ClientCertStoreTest : public ::testing::Test {
 public:
  T delegate_;
};

TYPED_TEST_CASE_P(ClientCertStoreTest);

TYPED_TEST_P(ClientCertStoreTest, EmptyQuery) {
  CertificateList certs;
  scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo());

  ClientCertIdentityList selected_identities;
  bool rv = this->delegate_.SelectClientCerts(certs, *request.get(),
                                              &selected_identities);
  EXPECT_TRUE(rv);
  EXPECT_EQ(0u, selected_identities.size());
}

// Verify that CertRequestInfo with empty |cert_authorities| matches all
// issuers, rather than no issuers.
TYPED_TEST_P(ClientCertStoreTest, AllIssuersAllowed) {
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1.pem"));
  ASSERT_TRUE(cert.get());

  std::vector<scoped_refptr<X509Certificate> > certs;
  certs.push_back(cert);
  scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo());

  ClientCertIdentityList selected_identities;
  bool rv = this->delegate_.SelectClientCerts(certs, *request.get(),
                                              &selected_identities);
  EXPECT_TRUE(rv);
  ASSERT_EQ(1u, selected_identities.size());
  EXPECT_TRUE(selected_identities[0]->certificate()->Equals(cert.get()));
}

// Verify that certificates are correctly filtered against CertRequestInfo with
// |cert_authorities| containing only |authority_1_DN|.
// Flaky: https://crbug.com/716730
TYPED_TEST_P(ClientCertStoreTest, DISABLED_CertAuthorityFiltering) {
  scoped_refptr<X509Certificate> cert_1(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1.pem"));
  ASSERT_TRUE(cert_1.get());
  scoped_refptr<X509Certificate> cert_2(
      ImportCertFromFile(GetTestCertsDirectory(), "client_2.pem"));
  ASSERT_TRUE(cert_2.get());

  std::vector<std::string> authority_1(
      1, std::string(reinterpret_cast<const char*>(kAuthority1DN),
                     sizeof(kAuthority1DN)));
  std::vector<std::string> authority_2(
      1, std::string(reinterpret_cast<const char*>(kAuthority2DN),
                     sizeof(kAuthority2DN)));
  EXPECT_TRUE(cert_1->IsIssuedByEncoded(authority_1));
  EXPECT_FALSE(cert_1->IsIssuedByEncoded(authority_2));
  EXPECT_TRUE(cert_2->IsIssuedByEncoded(authority_2));
  EXPECT_FALSE(cert_2->IsIssuedByEncoded(authority_1));

  std::vector<scoped_refptr<X509Certificate> > certs;
  certs.push_back(cert_1);
  certs.push_back(cert_2);
  scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo());
  request->cert_authorities = authority_1;

  ClientCertIdentityList selected_identities;
  bool rv = this->delegate_.SelectClientCerts(certs, *request.get(),
                                              &selected_identities);
  EXPECT_TRUE(rv);
  ASSERT_EQ(1u, selected_identities.size());
  EXPECT_TRUE(selected_identities[0]->certificate()->Equals(cert_1.get()));
}

REGISTER_TYPED_TEST_CASE_P(ClientCertStoreTest,
                           EmptyQuery,
                           AllIssuersAllowed,
                           DISABLED_CertAuthorityFiltering);

}  // namespace net

#endif  // NET_SSL_CLIENT_CERT_STORE_UNITTEST_INL_H_
