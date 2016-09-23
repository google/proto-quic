// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_store_nss.h"

#include <cert.h>
#include <certt.h>
#include <pk11pub.h>

#include <memory>
#include <string>

#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/client_cert_store_unittest-inl.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/test/cert_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

class ClientCertStoreNSSTestDelegate {
 public:
  ClientCertStoreNSSTestDelegate() {}

  bool SelectClientCerts(const CertificateList& input_certs,
                         const SSLCertRequestInfo& cert_request_info,
                         CertificateList* selected_certs) {
    // Filters |input_certs| using the logic being used to filter the system
    // store when GetClientCerts() is called.
    ClientCertStoreNSS::FilterCertsOnWorkerThread(
        input_certs, cert_request_info, selected_certs);
    return true;
  }
};

INSTANTIATE_TYPED_TEST_CASE_P(NSS,
                              ClientCertStoreTest,
                              ClientCertStoreNSSTestDelegate);

// Tests that ClientCertStoreNSS attempts to build a certificate chain by
// querying NSS before return a certificate.
TEST(ClientCertStoreNSSTest, BuildsCertificateChain) {
  // Set up a test DB and import client_1.pem and client_1_ca.pem.
  crypto::ScopedTestNSSDB test_db;
  scoped_refptr<X509Certificate> client_1(ImportClientCertAndKeyFromFile(
      GetTestCertsDirectory(), "client_1.pem", "client_1.pk8", test_db.slot()));
  ASSERT_TRUE(client_1.get());
  scoped_refptr<X509Certificate> client_1_ca(
      ImportCertFromFile(GetTestCertsDirectory(), "client_1_ca.pem"));
  ASSERT_TRUE(client_1_ca.get());
  ASSERT_EQ(SECSuccess,
            PK11_ImportCert(test_db.slot(), client_1_ca->os_cert_handle(),
                            CK_INVALID_HANDLE, "client_1_ca",
                            PR_FALSE /* includeTrust (unused) */));

  std::unique_ptr<ClientCertStoreNSS> store(
      new ClientCertStoreNSS(ClientCertStoreNSS::PasswordDelegateFactory()));

  {
    // Request certificates matching B CA, |client_1|'s issuer.
    scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo);
    request->cert_authorities.push_back(std::string(
        reinterpret_cast<const char*>(kAuthority1DN), sizeof(kAuthority1DN)));

    CertificateList selected_certs;
    base::RunLoop loop;
    store->GetClientCerts(*request.get(), &selected_certs, loop.QuitClosure());
    loop.Run();

    // The result be |client_1| with no intermediates.
    ASSERT_EQ(1u, selected_certs.size());
    scoped_refptr<X509Certificate> selected_cert = selected_certs[0];
    EXPECT_TRUE(X509Certificate::IsSameOSCert(client_1->os_cert_handle(),
                                              selected_cert->os_cert_handle()));
    ASSERT_EQ(0u, selected_cert->GetIntermediateCertificates().size());
  }

  {
    // Request certificates matching C Root CA, |client_1_ca|'s issuer.
    scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo);
    request->cert_authorities.push_back(
        std::string(reinterpret_cast<const char*>(kAuthorityRootDN),
                    sizeof(kAuthorityRootDN)));

    CertificateList selected_certs;
    base::RunLoop loop;
    store->GetClientCerts(*request.get(), &selected_certs, loop.QuitClosure());
    loop.Run();

    // The result be |client_1| with |client_1_ca| as an intermediate.
    ASSERT_EQ(1u, selected_certs.size());
    scoped_refptr<X509Certificate> selected_cert = selected_certs[0];
    EXPECT_TRUE(X509Certificate::IsSameOSCert(client_1->os_cert_handle(),
                                              selected_cert->os_cert_handle()));
    ASSERT_EQ(1u, selected_cert->GetIntermediateCertificates().size());
    EXPECT_TRUE(X509Certificate::IsSameOSCert(
        client_1_ca->os_cert_handle(),
        selected_cert->GetIntermediateCertificates()[0]));
  }
}

}  // namespace net
