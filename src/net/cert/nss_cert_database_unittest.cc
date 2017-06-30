// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/nss_cert_database.h"

#include <cert.h>
#include <certdb.h>
#include <pk11pub.h>

#include <algorithm>
#include <memory>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/lazy_instance.h"
#include "base/run_loop.h"
#include "base/strings/string16.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "crypto/scoped_nss_types.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/base/hash_value.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_proc_nss.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/third_party/mozilla_security_manager/nsNSSCertificateDB.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

// In NSS 3.13, CERTDB_VALID_PEER was renamed CERTDB_TERMINAL_RECORD. So we use
// the new name of the macro.
#if !defined(CERTDB_TERMINAL_RECORD)
#define CERTDB_TERMINAL_RECORD CERTDB_VALID_PEER
#endif

using base::ASCIIToUTF16;

namespace net {

namespace {

void SwapCertList(CertificateList* destination,
                  std::unique_ptr<CertificateList> source) {
  ASSERT_TRUE(destination);
  destination->swap(*source);
}

}  // namespace

class CertDatabaseNSSTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(test_nssdb_.is_open());
    cert_db_.reset(new NSSCertDatabase(
        crypto::ScopedPK11Slot(
            PK11_ReferenceSlot(test_nssdb_.slot())) /* public slot */,
        crypto::ScopedPK11Slot(
            PK11_ReferenceSlot(test_nssdb_.slot())) /* private slot */));
    public_slot_ = cert_db_->GetPublicSlot();

    // Test db should be empty at start of test.
    EXPECT_EQ(0U, ListCerts().size());
  }

  void TearDown() override {
    // Run the message loop to process any observer callbacks (e.g. for the
    // ClientSocketFactory singleton) so that the scoped ref ptrs created in
    // NSSCertDatabase::NotifyObservers* get released.
    base::RunLoop().RunUntilIdle();
  }

 protected:
  PK11SlotInfo* GetPublicSlot() { return public_slot_.get(); }

  static std::string ReadTestFile(const std::string& name) {
    std::string result;
    base::FilePath cert_path = GetTestCertsDirectory().AppendASCII(name);
    EXPECT_TRUE(base::ReadFileToString(cert_path, &result));
    return result;
  }

  static bool ReadCertIntoList(const std::string& name,
                               CertificateList* certs) {
    scoped_refptr<X509Certificate> cert(
        ImportCertFromFile(GetTestCertsDirectory(), name));
    if (!cert.get())
      return false;

    certs->push_back(cert);
    return true;
  }

  CertificateList ListCerts() {
    CertificateList result;
    CERTCertList* cert_list = PK11_ListCertsInSlot(test_nssdb_.slot());
    for (CERTCertListNode* node = CERT_LIST_HEAD(cert_list);
         !CERT_LIST_END(node, cert_list);
         node = CERT_LIST_NEXT(node)) {
      scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromHandle(
          node->cert, X509Certificate::OSCertHandles());
      if (!cert) {
        ADD_FAILURE() << "X509Certificate::CreateFromHandle failed";
        continue;
      }
      result.push_back(cert);
    }
    CERT_DestroyCertList(cert_list);

    // Sort the result so that test comparisons can be deterministic.
    std::sort(
        result.begin(), result.end(),
        [](const scoped_refptr<X509Certificate>& lhs,
           const scoped_refptr<X509Certificate>& rhs) {
          return SHA256HashValueLessThan()(
              X509Certificate::CalculateFingerprint256(lhs->os_cert_handle()),
              X509Certificate::CalculateFingerprint256(rhs->os_cert_handle()));
        });
    return result;
  }

  std::unique_ptr<NSSCertDatabase> cert_db_;
  const CertificateList empty_cert_list_;
  crypto::ScopedTestNSSDB test_nssdb_;
  crypto::ScopedPK11Slot public_slot_;
};

TEST_F(CertDatabaseNSSTest, ListCertsSync) {
  // This test isn't terribly useful, though it will at least let valgrind test
  // for leaks.
  CertificateList certs;
  cert_db_->ListCertsSync(&certs);
  // The test DB is empty, but let's assume there will always be something in
  // the other slots.
  EXPECT_LT(0U, certs.size());
}

TEST_F(CertDatabaseNSSTest, ListCerts) {
  // This test isn't terribly useful, though it will at least let valgrind test
  // for leaks.
  CertificateList certs;
  cert_db_->SetSlowTaskRunnerForTest(base::ThreadTaskRunnerHandle::Get());
  cert_db_->ListCerts(base::Bind(&SwapCertList, base::Unretained(&certs)));
  EXPECT_EQ(0U, certs.size());

  base::RunLoop().RunUntilIdle();

  // The test DB is empty, but let's assume there will always be something in
  // the other slots.
  EXPECT_LT(0U, certs.size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12WrongPassword) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(ERR_PKCS12_IMPORT_BAD_PASSWORD,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       base::string16(),
                                       true,  // is_extractable
                                       NULL));

  // Test db should still be empty.
  EXPECT_EQ(0U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12AsExtractableAndExportAgain) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       ASCIIToUTF16("12345"),
                                       true,  // is_extractable
                                       NULL));

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  EXPECT_EQ("testusercert",
            cert->subject().common_name);

  // TODO(mattm): move export test to separate test case?
  std::string exported_data;
  EXPECT_EQ(1, cert_db_->ExportToPKCS12(cert_list, ASCIIToUTF16("exportpw"),
                                        &exported_data));
  ASSERT_LT(0U, exported_data.size());
  // TODO(mattm): further verification of exported data?
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12Twice) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       ASCIIToUTF16("12345"),
                                       true,  // is_extractable
                                       NULL));
  EXPECT_EQ(1U, ListCerts().size());

  // NSS has a SEC_ERROR_PKCS12_DUPLICATE_DATA error, but it doesn't look like
  // it's ever used.  This test verifies that.
  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       ASCIIToUTF16("12345"),
                                       true,  // is_extractable
                                       NULL));
  EXPECT_EQ(1U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12AsUnextractableAndExportAgain) {
  std::string pkcs12_data = ReadTestFile("client.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       ASCIIToUTF16("12345"),
                                       false,  // is_extractable
                                       NULL));

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  EXPECT_EQ("testusercert",
            cert->subject().common_name);

  std::string exported_data;
  EXPECT_EQ(0, cert_db_->ExportToPKCS12(cert_list, ASCIIToUTF16("exportpw"),
                                        &exported_data));
}

// Importing a PKCS#12 file with a certificate but no corresponding
// private key should not mark an existing private key as unextractable.
TEST_F(CertDatabaseNSSTest, ImportFromPKCS12OnlyMarkIncludedKey) {
  std::string pkcs12_data = ReadTestFile("client.p12");
  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       ASCIIToUTF16("12345"),
                                       true,  // is_extractable
                                       NULL));

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());

  // Now import a PKCS#12 file with just a certificate but no private key.
  pkcs12_data = ReadTestFile("client-nokey.p12");
  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       ASCIIToUTF16("12345"),
                                       false,  // is_extractable
                                       NULL));

  cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());

  // Make sure the imported private key is still extractable.
  std::string exported_data;
  EXPECT_EQ(1, cert_db_->ExportToPKCS12(cert_list, ASCIIToUTF16("exportpw"),
                                        &exported_data));
  ASSERT_LT(0U, exported_data.size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12InvalidFile) {
  std::string pkcs12_data = "Foobarbaz";

  EXPECT_EQ(ERR_PKCS12_IMPORT_INVALID_FILE,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       base::string16(),
                                       true,  // is_extractable
                                       NULL));

  // Test db should still be empty.
  EXPECT_EQ(0U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12EmptyPassword) {
  std::string pkcs12_data = ReadTestFile("client-empty-password.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       base::string16(),
                                       true,  // is_extractable
                                       NULL));
  EXPECT_EQ(1U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportFromPKCS12NullPassword) {
  std::string pkcs12_data = ReadTestFile("client-null-password.p12");

  EXPECT_EQ(OK,
            cert_db_->ImportFromPKCS12(GetPublicSlot(),
                                       pkcs12_data,
                                       base::string16(),
                                       true,  // is_extractable
                                       NULL));
  EXPECT_EQ(1U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportCACert_SSLTrust) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(certs[0]->os_cert_handle()->isperm);

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));

  EXPECT_EQ(0U, failed.size());

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);
  EXPECT_EQ("Test Root CA", cert->subject().common_name);

  EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
            cert_db_->GetCertTrust(cert.get(), CA_CERT));

  EXPECT_EQ(unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA |
                     CERTDB_TRUSTED_CLIENT_CA),
            cert->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            cert->os_cert_handle()->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            cert->os_cert_handle()->trust->objectSigningFlags);
}

TEST_F(CertDatabaseNSSTest, ImportCACert_EmailTrust) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(certs[0]->os_cert_handle()->isperm);

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_EMAIL,
                                      &failed));

  EXPECT_EQ(0U, failed.size());

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);
  EXPECT_EQ("Test Root CA", cert->subject().common_name);

  EXPECT_EQ(NSSCertDatabase::TRUSTED_EMAIL,
            cert_db_->GetCertTrust(cert.get(), CA_CERT));

  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            cert->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA |
                     CERTDB_TRUSTED_CLIENT_CA),
            cert->os_cert_handle()->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            cert->os_cert_handle()->trust->objectSigningFlags);
}

TEST_F(CertDatabaseNSSTest, ImportCACert_ObjSignTrust) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(certs[0]->os_cert_handle()->isperm);

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_OBJ_SIGN,
                                      &failed));

  EXPECT_EQ(0U, failed.size());

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);
  EXPECT_EQ("Test Root CA", cert->subject().common_name);

  EXPECT_EQ(NSSCertDatabase::TRUSTED_OBJ_SIGN,
            cert_db_->GetCertTrust(cert.get(), CA_CERT));

  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            cert->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            cert->os_cert_handle()->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA |
                     CERTDB_TRUSTED_CLIENT_CA),
            cert->os_cert_handle()->trust->objectSigningFlags);
}

TEST_F(CertDatabaseNSSTest, ImportCA_NotCACert) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  EXPECT_FALSE(certs[0]->os_cert_handle()->isperm);

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  ASSERT_EQ(1U, failed.size());
  // Note: this compares pointers directly.  It's okay in this case because
  // ImportCACerts returns the same pointers that were passed in.  In the
  // general case IsSameOSCert should be used.
  EXPECT_EQ(certs[0], failed[0].certificate);
  EXPECT_THAT(failed[0].net_error, IsError(ERR_IMPORT_CA_CERT_NOT_CA));

  EXPECT_EQ(0U, ListCerts().size());
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchy) {
  CertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("dod_root_ca_2_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("dod_ca_17_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("www_us_army_mil_cert.der", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  // Have to specify email trust for the cert verification of the child cert to
  // work (see
  // http://mxr.mozilla.org/mozilla/source/security/nss/lib/certhigh/certvfy.c#752
  // "XXX This choice of trustType seems arbitrary.")
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  ASSERT_EQ(2U, failed.size());
  EXPECT_EQ("DOD CA-17", failed[0].certificate->subject().common_name);
  EXPECT_THAT(failed[0].net_error,
              IsError(ERR_FAILED));  // The certificate expired.
  EXPECT_EQ("www.us.army.mil", failed[1].certificate->subject().common_name);
  EXPECT_THAT(failed[1].net_error, IsError(ERR_IMPORT_CA_CERT_NOT_CA));

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("DoD Root CA 2", cert_list[0]->subject().common_name);
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchyDupeRoot) {
  CertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("dod_root_ca_2_cert.der", &certs));

  // First import just the root.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  EXPECT_EQ(0U, failed.size());
  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("DoD Root CA 2", cert_list[0]->subject().common_name);

  ASSERT_TRUE(ReadCertIntoList("dod_ca_17_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("www_us_army_mil_cert.der", &certs));

  // Now import with the other certs in the list too.  Even though the root is
  // already present, we should still import the rest.
  failed.clear();
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  ASSERT_EQ(3U, failed.size());
  EXPECT_EQ("DoD Root CA 2", failed[0].certificate->subject().common_name);
  EXPECT_THAT(failed[0].net_error, IsError(ERR_IMPORT_CERT_ALREADY_EXISTS));
  EXPECT_EQ("DOD CA-17", failed[1].certificate->subject().common_name);
  EXPECT_THAT(failed[1].net_error,
              IsError(ERR_FAILED));  // The certificate expired.
  EXPECT_EQ("www.us.army.mil", failed[2].certificate->subject().common_name);
  EXPECT_THAT(failed[2].net_error, IsError(ERR_IMPORT_CA_CERT_NOT_CA));

  cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("DoD Root CA 2", cert_list[0]->subject().common_name);
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchyUntrusted) {
  CertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("dod_root_ca_2_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("dod_ca_17_cert.der", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(certs, NSSCertDatabase::TRUST_DEFAULT,
                                      &failed));

  ASSERT_EQ(1U, failed.size());
  EXPECT_EQ("DOD CA-17", failed[0].certificate->subject().common_name);
  // TODO(mattm): should check for net error equivalent of
  // SEC_ERROR_UNTRUSTED_ISSUER
  EXPECT_THAT(failed[0].net_error, IsError(ERR_FAILED));

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("DoD Root CA 2", cert_list[0]->subject().common_name);
}

TEST_F(CertDatabaseNSSTest, ImportCACertHierarchyTree) {
  CertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("dod_root_ca_2_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("dod_ca_13_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("dod_ca_17_cert.der", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL,
      &failed));

  EXPECT_EQ(2U, failed.size());
  EXPECT_EQ("DOD CA-13", failed[0].certificate->subject().common_name);
  EXPECT_THAT(failed[0].net_error,
              IsError(ERR_FAILED));  // The certificate expired.
  EXPECT_EQ("DOD CA-17", failed[1].certificate->subject().common_name);
  EXPECT_THAT(failed[1].net_error,
              IsError(ERR_FAILED));  // The certificate expired.

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("DoD Root CA 2", cert_list[0]->subject().common_name);
}

TEST_F(CertDatabaseNSSTest, ImportCACertNotHierarchy) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());
  ASSERT_TRUE(ReadCertIntoList("dod_ca_13_cert.der", &certs));
  ASSERT_TRUE(ReadCertIntoList("dod_ca_17_cert.der", &certs));

  // Import it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(
      certs, NSSCertDatabase::TRUSTED_SSL | NSSCertDatabase::TRUSTED_EMAIL |
      NSSCertDatabase::TRUSTED_OBJ_SIGN, &failed));

  ASSERT_EQ(2U, failed.size());
  // TODO(mattm): should check for net error equivalent of
  // SEC_ERROR_UNKNOWN_ISSUER
  EXPECT_EQ("DOD CA-13", failed[0].certificate->subject().common_name);
  EXPECT_THAT(failed[0].net_error, IsError(ERR_FAILED));
  EXPECT_EQ("DOD CA-17", failed[1].certificate->subject().common_name);
  EXPECT_THAT(failed[1].net_error, IsError(ERR_FAILED));

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  EXPECT_EQ("Test Root CA", cert_list[0]->subject().common_name);
}

// Test importing a server cert + chain to the NSS DB with default trust. After
// importing, all the certs should be found in the DB and should have default
// trust flags.
TEST_F(CertDatabaseNSSTest, ImportServerCert) {
  scoped_refptr<X509Certificate> input_server_cert = ImportCertFromFile(
      GetTestCertsDirectory(), "ok_cert_by_intermediate.pem");
  scoped_refptr<X509Certificate> input_intermediate_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "intermediate_ca_cert.pem");
  scoped_refptr<X509Certificate> input_root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");

  // Import the server and its chain.
  CertificateList certs_to_import = {input_server_cert, input_intermediate_cert,
                                     input_root_cert};
  ASSERT_EQ(3U, certs_to_import.size());

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs_to_import, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());

  // All the certs in the imported list should now be found in the NSS DB.
  CertificateList cert_list = ListCerts();
  ASSERT_EQ(3U, cert_list.size());
  scoped_refptr<X509Certificate> found_server_cert(cert_list[1]);
  scoped_refptr<X509Certificate> found_intermediate_cert(cert_list[2]);
  scoped_refptr<X509Certificate> found_root_cert(cert_list[0]);
  EXPECT_EQ("127.0.0.1", found_server_cert->subject().common_name);
  EXPECT_EQ("Test Intermediate CA",
            found_intermediate_cert->subject().common_name);
  EXPECT_EQ("Test Root CA", found_root_cert->subject().common_name);

  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(found_server_cert.get(), SERVER_CERT));
  EXPECT_EQ(0U, found_server_cert->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(found_intermediate_cert.get(), CA_CERT));
  EXPECT_EQ(0U, found_intermediate_cert->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(found_root_cert.get(), CA_CERT));
  EXPECT_EQ(0U, found_root_cert->os_cert_handle()->trust->sslFlags);

  // Verification fails, as the intermediate & CA certs are imported without
  // trust.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(found_server_cert.get(), "127.0.0.1", std::string(),
                          flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, ImportServerCert_SelfSigned) {
  CertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("punycodetest.pem", &certs));

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));

  EXPECT_EQ(0U, failed.size());

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> puny_cert(cert_list[0]);

  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(puny_cert.get(), SERVER_CERT));
  EXPECT_EQ(0U, puny_cert->os_cert_handle()->trust->sslFlags);

  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(puny_cert.get(), "xn--wgv71a119e.com", std::string(),
                          flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, ImportServerCert_SelfSigned_Trusted) {
  CertificateList certs;
  ASSERT_TRUE(ReadCertIntoList("punycodetest.pem", &certs));

  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUSTED_SSL,
                                         &failed));

  EXPECT_EQ(0U, failed.size());

  CertificateList cert_list = ListCerts();
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> puny_cert(cert_list[0]);

  EXPECT_EQ(NSSCertDatabase::TRUSTED_SSL,
            cert_db_->GetCertTrust(puny_cert.get(), SERVER_CERT));
  EXPECT_EQ(unsigned(CERTDB_TRUSTED | CERTDB_TERMINAL_RECORD),
            puny_cert->os_cert_handle()->trust->sslFlags);

  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(puny_cert.get(), "xn--wgv71a119e.com", std::string(),
                          flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, ImportCaAndServerCert) {
  CertificateList ca_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import CA cert and trust it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(certs, NSSCertDatabase::TRUST_DEFAULT,
                                         &failed));
  EXPECT_EQ(0U, failed.size());

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                          NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, ImportCaAndServerCert_DistrustServer) {
  CertificateList ca_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import CA cert and trust it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert without inheriting trust from issuer (explicit
  // distrust).
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs, NSSCertDatabase::DISTRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::DISTRUSTED_SSL,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  EXPECT_EQ(unsigned(CERTDB_TERMINAL_RECORD),
            certs[0]->os_cert_handle()->trust->sslFlags);

  // Server cert should fail to verify.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                          NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_EQ(CERT_STATUS_REVOKED, verify_result.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa) {
  CertificateList ca_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-root.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import Root CA cert and distrust it.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::DISTRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList intermediate_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-ee-by-2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                          NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Trust the root cert and distrust the intermediate.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      ca_certs[0].get(), CA_CERT, NSSCertDatabase::TRUSTED_SSL));
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::DISTRUSTED_SSL));
  EXPECT_EQ(
      unsigned(CERTDB_VALID_CA | CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA),
      ca_certs[0]->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            ca_certs[0]->os_cert_handle()->trust->emailFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            ca_certs[0]->os_cert_handle()->trust->objectSigningFlags);
  EXPECT_EQ(unsigned(CERTDB_TERMINAL_RECORD),
            intermediate_certs[0]->os_cert_handle()->trust->sslFlags);
  EXPECT_EQ(unsigned(CERTDB_VALID_CA),
            intermediate_certs[0]->os_cert_handle()->trust->emailFlags);
  EXPECT_EQ(
      unsigned(CERTDB_VALID_CA),
      intermediate_certs[0]->os_cert_handle()->trust->objectSigningFlags);

  // Server cert should fail to verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                              NULL, empty_cert_list_, &verify_result2);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_EQ(CERT_STATUS_REVOKED, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa2) {
  if (NSS_VersionCheck("3.14.2") && !NSS_VersionCheck("3.15")) {
    // See http://bugzil.la/863947 for details.
    LOG(INFO) << "Skipping test for NSS 3.14.2 - NSS 3.15";
    return;
  }

  NSSCertDatabase::ImportCertFailureList failed;

  CertificateList intermediate_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-ee-by-2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                          NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Without explicit trust of the intermediate, verification should fail.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

  // Server cert should fail to verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                              NULL, empty_cert_list_, &verify_result2);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa3) {
  if (NSS_VersionCheck("3.14.2") && !NSS_VersionCheck("3.15")) {
    // See http://bugzil.la/863947 for details.
    LOG(INFO) << "Skipping test for NSS 3.14.2 - NSS 3.15";
    return;
  }

  NSSCertDatabase::ImportCertFailureList failed;

  CertificateList ca_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-root.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import Root CA cert and default trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUST_DEFAULT,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList intermediate_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(intermediate_certs,
                                      NSSCertDatabase::TRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-ee-by-2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should verify.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                          NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  // Without explicit trust of the intermediate, verification should fail.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

  // Server cert should fail to verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                              NULL, empty_cert_list_, &verify_result2);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result2.cert_status);
}

TEST_F(CertDatabaseNSSTest, TrustIntermediateCa4) {
  NSSCertDatabase::ImportCertFailureList failed;

  CertificateList ca_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-root.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_certs.size());

  // Import Root CA cert and trust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(ca_certs, NSSCertDatabase::TRUSTED_SSL,
                                      &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList intermediate_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, intermediate_certs.size());

  // Import Intermediate CA cert and distrust it.
  EXPECT_TRUE(cert_db_->ImportCACerts(
        intermediate_certs, NSSCertDatabase::DISTRUSTED_SSL, &failed));
  EXPECT_EQ(0U, failed.size());

  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "2048-rsa-ee-by-2048-rsa-intermediate.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  // Server cert should not verify.
  scoped_refptr<CertVerifyProc> verify_proc(new CertVerifyProcNSS());
  int flags = 0;
  CertVerifyResult verify_result;
  int error =
      verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                          NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
  EXPECT_EQ(CERT_STATUS_REVOKED, verify_result.cert_status);

  // Without explicit distrust of the intermediate, verification should succeed.
  EXPECT_TRUE(cert_db_->SetCertTrust(
      intermediate_certs[0].get(), CA_CERT, NSSCertDatabase::TRUST_DEFAULT));

  // Server cert should verify.
  CertVerifyResult verify_result2;
  error = verify_proc->Verify(certs[0].get(), "127.0.0.1", std::string(), flags,
                              NULL, empty_cert_list_, &verify_result2);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result2.cert_status);
}

// Importing two certificates with the same issuer and subject common name,
// but overall distinct subject names, should succeed and generate a unique
// nickname for the second certificate.
TEST_F(CertDatabaseNSSTest, ImportDuplicateCommonName) {
  CertificateList certs =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "duplicate_cn_1.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  EXPECT_EQ(0U, ListCerts().size());

  // Import server cert with default trust.
  NSSCertDatabase::ImportCertFailureList failed;
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs[0].get(), SERVER_CERT));

  CertificateList new_certs = ListCerts();
  ASSERT_EQ(1U, new_certs.size());

  // Now attempt to import a different certificate with the same common name.
  CertificateList certs2 =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "duplicate_cn_2.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs2.size());

  // Import server cert with default trust.
  EXPECT_TRUE(cert_db_->ImportServerCert(
      certs2, NSSCertDatabase::TRUST_DEFAULT, &failed));
  EXPECT_EQ(0U, failed.size());
  EXPECT_EQ(NSSCertDatabase::TRUST_DEFAULT,
            cert_db_->GetCertTrust(certs2[0].get(), SERVER_CERT));

  new_certs = ListCerts();
  ASSERT_EQ(2U, new_certs.size());
  EXPECT_STRNE(new_certs[0]->os_cert_handle()->nickname,
               new_certs[1]->os_cert_handle()->nickname);
}

}  // namespace net
