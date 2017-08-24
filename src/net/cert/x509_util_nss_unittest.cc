// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_nss.h"

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

std::string BytesForNSSCert(CERTCertificate* cert) {
  std::string der_encoded;
  if (!x509_util::GetDEREncoded(cert, &der_encoded))
    ADD_FAILURE();
  return der_encoded;
}

std::string BytesForX509CertHandle(X509Certificate::OSCertHandle handle) {
  std::string result;
  if (!X509Certificate::GetDEREncoded(handle, &result))
    ADD_FAILURE();
  return result;
}

std::string BytesForX509Cert(X509Certificate* cert) {
  return BytesForX509CertHandle(cert->os_cert_handle());
}

}  // namespace

TEST(X509UtilNSSTest, IsSameCertificate) {
  ScopedCERTCertificate google_nss_cert(
      x509_util::CreateCERTCertificateFromBytes(google_der,
                                                arraysize(google_der)));
  ASSERT_TRUE(google_nss_cert);

  ScopedCERTCertificate google_nss_cert2(
      x509_util::CreateCERTCertificateFromBytes(google_der,
                                                arraysize(google_der)));
  ASSERT_TRUE(google_nss_cert2);

  ScopedCERTCertificate webkit_nss_cert(
      x509_util::CreateCERTCertificateFromBytes(webkit_der,
                                                arraysize(webkit_der)));
  ASSERT_TRUE(webkit_nss_cert);

  scoped_refptr<X509Certificate> google_x509_cert(
      X509Certificate::CreateFromBytes(
          reinterpret_cast<const char*>(google_der), arraysize(google_der)));
  ASSERT_TRUE(google_x509_cert);

  scoped_refptr<X509Certificate> webkit_x509_cert(
      X509Certificate::CreateFromBytes(
          reinterpret_cast<const char*>(webkit_der), arraysize(webkit_der)));
  ASSERT_TRUE(webkit_x509_cert);

  EXPECT_TRUE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                           google_nss_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                           google_nss_cert2.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                           google_x509_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(google_x509_cert.get(),
                                           google_nss_cert.get()));

  EXPECT_TRUE(x509_util::IsSameCertificate(webkit_nss_cert.get(),
                                           webkit_nss_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(webkit_nss_cert.get(),
                                           webkit_x509_cert.get()));
  EXPECT_TRUE(x509_util::IsSameCertificate(webkit_x509_cert.get(),
                                           webkit_nss_cert.get()));

  EXPECT_FALSE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                            webkit_nss_cert.get()));
  EXPECT_FALSE(x509_util::IsSameCertificate(google_nss_cert.get(),
                                            webkit_x509_cert.get()));
  EXPECT_FALSE(x509_util::IsSameCertificate(google_x509_cert.get(),
                                            webkit_nss_cert.get()));
}

TEST(X509UtilNSSTest, CreateCERTCertificateFromBytes) {
  ScopedCERTCertificate google_cert(x509_util::CreateCERTCertificateFromBytes(
      google_der, arraysize(google_der)));
  ASSERT_TRUE(google_cert);
  EXPECT_STREQ(
      "CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
      google_cert->subjectName);
}

TEST(X509UtilNSSTest, CreateCERTCertificateFromBytesGarbage) {
  static const uint8_t garbage_data[] = "garbage";
  EXPECT_EQ(nullptr,
            x509_util::CreateCERTCertificateFromBytes(garbage_data, 0));
  EXPECT_EQ(nullptr, x509_util::CreateCERTCertificateFromBytes(
                         garbage_data, arraysize(garbage_data)));
}

TEST(X509UtilNSSTest, CreateCERTCertificateFromX509Certificate) {
  scoped_refptr<X509Certificate> x509_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(x509_cert);
  ScopedCERTCertificate nss_cert =
      x509_util::CreateCERTCertificateFromX509Certificate(x509_cert.get());
  ASSERT_TRUE(nss_cert);
  EXPECT_STREQ("CN=127.0.0.1,O=Test CA,L=Mountain View,ST=California,C=US",
               nss_cert->subjectName);
}

TEST(X509UtilNSSTest, CreateCERTCertificateListFromX509Certificate) {
  scoped_refptr<X509Certificate> x509_cert = CreateCertificateChainFromFile(
      GetTestCertsDirectory(), "multi-root-chain1.pem",
      X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  ASSERT_TRUE(x509_cert);
  EXPECT_EQ(3U, x509_cert->GetIntermediateCertificates().size());

  ScopedCERTCertificateList nss_certs =
      x509_util::CreateCERTCertificateListFromX509Certificate(x509_cert.get());
  ASSERT_EQ(4U, nss_certs.size());
  for (int i = 0; i < 4; ++i)
    ASSERT_TRUE(nss_certs[i]);

  EXPECT_EQ(BytesForX509Cert(x509_cert.get()),
            BytesForNSSCert(nss_certs[0].get()));
  EXPECT_EQ(BytesForX509CertHandle(x509_cert->GetIntermediateCertificates()[0]),
            BytesForNSSCert(nss_certs[1].get()));
  EXPECT_EQ(BytesForX509CertHandle(x509_cert->GetIntermediateCertificates()[1]),
            BytesForNSSCert(nss_certs[2].get()));
  EXPECT_EQ(BytesForX509CertHandle(x509_cert->GetIntermediateCertificates()[2]),
            BytesForNSSCert(nss_certs[3].get()));
}

TEST(X509UtilNSSTest, CreateCERTCertificateListFromBytes) {
  base::FilePath cert_path =
      GetTestCertsDirectory().AppendASCII("multi-root-chain1.pem");
  std::string cert_data;
  ASSERT_TRUE(base::ReadFileToString(cert_path, &cert_data));

  ScopedCERTCertificateList certs =
      x509_util::CreateCERTCertificateListFromBytes(
          cert_data.data(), cert_data.size(), X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(4U, certs.size());
  EXPECT_STREQ("CN=127.0.0.1,O=Test CA,L=Mountain View,ST=California,C=US",
               certs[0]->subjectName);
  EXPECT_STREQ("CN=B CA - Multi-root", certs[1]->subjectName);
  EXPECT_STREQ("CN=C CA - Multi-root", certs[2]->subjectName);
  EXPECT_STREQ("CN=D Root CA - Multi-root", certs[3]->subjectName);
}

TEST(X509UtilNSSTest, DupCERTCertificate) {
  ScopedCERTCertificate cert(x509_util::CreateCERTCertificateFromBytes(
      google_der, arraysize(google_der)));
  ASSERT_TRUE(cert);

  ScopedCERTCertificate cert2 = x509_util::DupCERTCertificate(cert.get());
  // Both handles should hold a reference to the same CERTCertificate object.
  ASSERT_EQ(cert.get(), cert2.get());

  // Release the initial handle.
  cert.reset();
  // The duped handle should still be safe to access.
  EXPECT_STREQ(
      "CN=www.google.com,O=Google Inc,L=Mountain View,ST=California,C=US",
      cert2->subjectName);
}

TEST(X509UtilNSSTest, CreateX509CertificateFromCERTCertificate_NoChain) {
  ScopedCERTCertificate nss_cert(x509_util::CreateCERTCertificateFromBytes(
      google_der, arraysize(google_der)));
  ASSERT_TRUE(nss_cert);
  scoped_refptr<X509Certificate> x509_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(nss_cert.get());
  EXPECT_EQ(BytesForNSSCert(nss_cert.get()), BytesForX509Cert(x509_cert.get()));
  EXPECT_TRUE(x509_cert->GetIntermediateCertificates().empty());
}

TEST(X509UtilNSSTest, CreateX509CertificateFromCERTCertificate_EmptyChain) {
  ScopedCERTCertificate nss_cert(x509_util::CreateCERTCertificateFromBytes(
      google_der, arraysize(google_der)));
  ASSERT_TRUE(nss_cert);
  scoped_refptr<X509Certificate> x509_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(
          nss_cert.get(), std::vector<CERTCertificate*>());
  EXPECT_EQ(BytesForNSSCert(nss_cert.get()), BytesForX509Cert(x509_cert.get()));
  EXPECT_TRUE(x509_cert->GetIntermediateCertificates().empty());
}

TEST(X509UtilNSSTest, CreateX509CertificateFromCERTCertificate_WithChain) {
  ScopedCERTCertificate nss_cert(x509_util::CreateCERTCertificateFromBytes(
      google_der, arraysize(google_der)));
  ASSERT_TRUE(nss_cert);
  ScopedCERTCertificate nss_cert2(x509_util::CreateCERTCertificateFromBytes(
      webkit_der, arraysize(webkit_der)));
  ASSERT_TRUE(nss_cert2);

  std::vector<CERTCertificate*> chain;
  chain.push_back(nss_cert2.get());

  scoped_refptr<X509Certificate> x509_cert =
      x509_util::CreateX509CertificateFromCERTCertificate(nss_cert.get(),
                                                          chain);
  EXPECT_EQ(BytesForNSSCert(nss_cert.get()), BytesForX509Cert(x509_cert.get()));
  ASSERT_EQ(1U, x509_cert->GetIntermediateCertificates().size());
  EXPECT_EQ(BytesForX509CertHandle(x509_cert->GetIntermediateCertificates()[0]),
            BytesForNSSCert(nss_cert2.get()));
}

TEST(X509UtilNSSTest, GetDEREncoded) {
  ScopedCERTCertificate google_cert(x509_util::CreateCERTCertificateFromBytes(
      google_der, arraysize(google_der)));
  ASSERT_TRUE(google_cert);
  std::string der_encoded;
  ASSERT_TRUE(x509_util::GetDEREncoded(google_cert.get(), &der_encoded));
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(google_der),
                        arraysize(google_der)),
            der_encoded);
}

TEST(X509UtilNSSTest, GetDefaultNickname) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "no_subject_common_name_cert.pem"));
  ASSERT_TRUE(test_cert);

  std::string nickname = x509_util::GetDefaultUniqueNickname(
      test_cert->os_cert_handle(), USER_CERT, nullptr /*slot*/);
  EXPECT_EQ(
      "wtc@google.com's COMODO Client Authentication and "
      "Secure Email CA ID",
      nickname);
}

TEST(X509UtilNSSTest, GetCERTNameDisplayName_CN) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "ok_cert.pem"));
  ASSERT_TRUE(test_cert);

  std::string name =
      x509_util::GetCERTNameDisplayName(&test_cert->os_cert_handle()->subject);
  EXPECT_EQ("127.0.0.1", name);
  EXPECT_EQ(test_cert->subject().GetDisplayName(), name);
}

TEST(X509UtilNSSTest, GetCERTNameDisplayName_O) {
  base::FilePath certs_dir =
      GetTestNetDataDirectory().AppendASCII("parse_certificate_unittest");

  scoped_refptr<X509Certificate> test_cert(
      ImportCertFromFile(certs_dir, "subject_t61string.pem"));
  ASSERT_TRUE(test_cert);

  std::string name =
      x509_util::GetCERTNameDisplayName(&test_cert->os_cert_handle()->subject);
  EXPECT_EQ(
      " !\"#$%&'()*+,-./"
      "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
      "abcdefghijklmnopqrstuvwxyz{|}~"
      " ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæç"
      "èéêëìíîïðñòóôõö÷øùúûüýþÿ",
      name);
  EXPECT_EQ(test_cert->subject().GetDisplayName(), name);
}

TEST(X509UtilNSSTest, ParseClientSubjectAltNames) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  // This cert contains one rfc822Name field, and one Microsoft UPN
  // otherName field.
  scoped_refptr<X509Certificate> san_cert =
      ImportCertFromFile(certs_dir, "client_3.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), san_cert.get());

  std::vector<std::string> rfc822_names;
  x509_util::GetRFC822SubjectAltNames(san_cert->os_cert_handle(),
                                      &rfc822_names);
  ASSERT_EQ(1U, rfc822_names.size());
  EXPECT_EQ("santest@example.com", rfc822_names[0]);

  std::vector<std::string> upn_names;
  x509_util::GetUPNSubjectAltNames(san_cert->os_cert_handle(), &upn_names);
  ASSERT_EQ(1U, upn_names.size());
  EXPECT_EQ("santest@ad.corp.example.com", upn_names[0]);
}

}  // namespace net
