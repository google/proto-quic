// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_issuer_source_static.h"

#include "base/bind.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/test_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

void NotCalled(CertIssuerSource::Request* req) {
  ADD_FAILURE() << "NotCalled was called";
}

::testing::AssertionResult ReadTestPem(const std::string& file_name,
                                       const std::string& block_name,
                                       std::string* result) {
  const PemBlockMapping mappings[] = {
      {block_name.c_str(), result},
  };

  return ReadTestDataFromPemFile(file_name, mappings);
}

::testing::AssertionResult ReadTestCert(
    const std::string& file_name,
    scoped_refptr<ParsedCertificate>* result) {
  std::string der;
  ::testing::AssertionResult r =
      ReadTestPem("net/data/cert_issuer_source_static_unittest/" + file_name,
                  "CERTIFICATE", &der);
  if (!r)
    return r;
  CertErrors errors;
  *result = ParsedCertificate::Create(der, {}, &errors);
  if (!*result) {
    return ::testing::AssertionFailure()
           << "ParsedCertificate::Create() failed:\n"
           << errors.ToDebugString();
  }
  return ::testing::AssertionSuccess();
}

class CertIssuerSourceStaticTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(ReadTestCert("root.pem", &root_));
    ASSERT_TRUE(ReadTestCert("i1_1.pem", &i1_1_));
    ASSERT_TRUE(ReadTestCert("i1_2.pem", &i1_2_));
    ASSERT_TRUE(ReadTestCert("i2.pem", &i2_));
    ASSERT_TRUE(ReadTestCert("c1.pem", &c1_));
    ASSERT_TRUE(ReadTestCert("c2.pem", &c2_));
    ASSERT_TRUE(ReadTestCert("d.pem", &d_));
  }

  void AddAllCerts(CertIssuerSourceStatic* source) {
    source->AddCert(root_);
    source->AddCert(i1_1_);
    source->AddCert(i1_2_);
    source->AddCert(i2_);
    source->AddCert(c1_);
    source->AddCert(c2_);
    source->AddCert(d_);
  }

 protected:
  scoped_refptr<ParsedCertificate> root_;
  scoped_refptr<ParsedCertificate> i1_1_;
  scoped_refptr<ParsedCertificate> i1_2_;
  scoped_refptr<ParsedCertificate> i2_;
  scoped_refptr<ParsedCertificate> c1_;
  scoped_refptr<ParsedCertificate> c2_;
  scoped_refptr<ParsedCertificate> d_;
};

TEST_F(CertIssuerSourceStaticTest, NoMatch) {
  CertIssuerSourceStatic source;
  source.AddCert(root_);

  ParsedCertificateList issuers;
  source.SyncGetIssuersOf(c1_.get(), &issuers);
  ASSERT_EQ(0U, issuers.size());
}

TEST_F(CertIssuerSourceStaticTest, OneMatch) {
  CertIssuerSourceStatic source;
  AddAllCerts(&source);

  ParsedCertificateList issuers;
  source.SyncGetIssuersOf(i1_1_.get(), &issuers);
  ASSERT_EQ(1U, issuers.size());
  EXPECT_TRUE(issuers[0] == root_);

  issuers.clear();
  source.SyncGetIssuersOf(d_.get(), &issuers);
  ASSERT_EQ(1U, issuers.size());
  EXPECT_TRUE(issuers[0] == i2_);
}

TEST_F(CertIssuerSourceStaticTest, MultipleMatches) {
  CertIssuerSourceStatic source;
  AddAllCerts(&source);

  ParsedCertificateList issuers;
  source.SyncGetIssuersOf(c1_.get(), &issuers);

  ASSERT_EQ(2U, issuers.size());
  EXPECT_TRUE(std::find(issuers.begin(), issuers.end(), i1_1_) !=
              issuers.end());
  EXPECT_TRUE(std::find(issuers.begin(), issuers.end(), i1_2_) !=
              issuers.end());
}

// Searching for the issuer of a self-issued cert returns the same cert if it
// happens to be in the CertIssuerSourceStatic.
// Conceptually this makes sense, though probably not very useful in practice.
// Doesn't hurt anything though.
TEST_F(CertIssuerSourceStaticTest, SelfIssued) {
  CertIssuerSourceStatic source;
  AddAllCerts(&source);

  ParsedCertificateList issuers;
  source.SyncGetIssuersOf(root_.get(), &issuers);

  ASSERT_EQ(1U, issuers.size());
  EXPECT_TRUE(issuers[0] == root_);
}

// CertIssuerSourceStatic never returns results asynchronously.
TEST_F(CertIssuerSourceStaticTest, IsNotAsync) {
  CertIssuerSourceStatic source;
  source.AddCert(i1_1_);
  std::unique_ptr<CertIssuerSource::Request> request;
  source.AsyncGetIssuersOf(c1_.get(), base::Bind(&NotCalled), &request);
  EXPECT_EQ(nullptr, request);
}

}  // namespace

}  // namespace net
