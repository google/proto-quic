// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_store_nss.h"

#include <cert.h>
#include <certt.h>
#include <pk11pub.h>

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/client_cert_identity_test_util.h"
#include "net/ssl/client_cert_store_unittest-inl.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_private_key_test_util.h"
#include "net/test/cert_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

void SaveIdentitiesAndQuitCallback(ClientCertIdentityList* out_identities,
                                   base::Closure quit_closure,
                                   ClientCertIdentityList in_identities) {
  *out_identities = std::move(in_identities);
  quit_closure.Run();
}

void SavePrivateKeyAndQuitCallback(scoped_refptr<net::SSLPrivateKey>* out_key,
                                   base::Closure quit_closure,
                                   scoped_refptr<net::SSLPrivateKey> in_key) {
  *out_key = std::move(in_key);
  quit_closure.Run();
}

}  // namespace

class ClientCertStoreNSSTestDelegate {
 public:
  ClientCertStoreNSSTestDelegate() {}

  bool SelectClientCerts(const CertificateList& input_certs,
                         const SSLCertRequestInfo& cert_request_info,
                         ClientCertIdentityList* selected_identities) {
    *selected_identities =
        FakeClientCertIdentityListFromCertificateList(input_certs);

    // Filters |selected_identities| using the logic being used to filter the
    // system store when GetClientCerts() is called.
    ClientCertStoreNSS::FilterCertsOnWorkerThread(selected_identities,
                                                  cert_request_info);
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
  std::string pkcs8_key;
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("client_1.pk8"), &pkcs8_key));

  std::unique_ptr<ClientCertStoreNSS> store(
      new ClientCertStoreNSS(ClientCertStoreNSS::PasswordDelegateFactory()));

  // All NSS keys are expected to have the same hash preferences.
  const std::vector<SSLPrivateKey::Hash> expected_hashes = {
      SSLPrivateKey::Hash::SHA512, SSLPrivateKey::Hash::SHA384,
      SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1,
  };

  {
    // Request certificates matching B CA, |client_1|'s issuer.
    scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo);
    request->cert_authorities.push_back(std::string(
        reinterpret_cast<const char*>(kAuthority1DN), sizeof(kAuthority1DN)));

    ClientCertIdentityList selected_identities;
    base::RunLoop loop;
    store->GetClientCerts(*request.get(),
                          base::Bind(SaveIdentitiesAndQuitCallback,
                                     &selected_identities, loop.QuitClosure()));
    loop.Run();

    // The result be |client_1| with no intermediates.
    ASSERT_EQ(1u, selected_identities.size());
    scoped_refptr<X509Certificate> selected_cert =
        selected_identities[0]->certificate();
    EXPECT_TRUE(X509Certificate::IsSameOSCert(client_1->os_cert_handle(),
                                              selected_cert->os_cert_handle()));
    ASSERT_EQ(0u, selected_cert->GetIntermediateCertificates().size());

    scoped_refptr<SSLPrivateKey> ssl_private_key;
    base::RunLoop key_loop;
    selected_identities[0]->AcquirePrivateKey(
        base::Bind(SavePrivateKeyAndQuitCallback, &ssl_private_key,
                   key_loop.QuitClosure()));
    key_loop.Run();

    ASSERT_TRUE(ssl_private_key);
    EXPECT_EQ(expected_hashes, ssl_private_key->GetDigestPreferences());
    TestSSLPrivateKeyMatches(ssl_private_key.get(), pkcs8_key);
  }

  {
    // Request certificates matching C Root CA, |client_1_ca|'s issuer.
    scoped_refptr<SSLCertRequestInfo> request(new SSLCertRequestInfo);
    request->cert_authorities.push_back(
        std::string(reinterpret_cast<const char*>(kAuthorityRootDN),
                    sizeof(kAuthorityRootDN)));

    ClientCertIdentityList selected_identities;
    base::RunLoop loop;
    store->GetClientCerts(*request.get(),
                          base::Bind(SaveIdentitiesAndQuitCallback,
                                     &selected_identities, loop.QuitClosure()));
    loop.Run();

    // The result be |client_1| with |client_1_ca| as an intermediate.
    ASSERT_EQ(1u, selected_identities.size());
    scoped_refptr<X509Certificate> selected_cert =
        selected_identities[0]->certificate();
    EXPECT_TRUE(X509Certificate::IsSameOSCert(client_1->os_cert_handle(),
                                              selected_cert->os_cert_handle()));
    ASSERT_EQ(1u, selected_cert->GetIntermediateCertificates().size());
    EXPECT_TRUE(X509Certificate::IsSameOSCert(
        client_1_ca->os_cert_handle(),
        selected_cert->GetIntermediateCertificates()[0]));

    scoped_refptr<SSLPrivateKey> ssl_private_key;
    base::RunLoop key_loop;
    selected_identities[0]->AcquirePrivateKey(
        base::Bind(SavePrivateKeyAndQuitCallback, &ssl_private_key,
                   key_loop.QuitClosure()));
    key_loop.Run();
    ASSERT_TRUE(ssl_private_key);
    EXPECT_EQ(expected_hashes, ssl_private_key->GetDigestPreferences());
    TestSSLPrivateKeyMatches(ssl_private_key.get(), pkcs8_key);
  }
}

// TODO(mattm): is it possible to unittest slot unlocking?

}  // namespace net
