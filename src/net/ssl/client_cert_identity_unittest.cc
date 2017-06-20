// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_identity.h"

#include "base/memory/ptr_util.h"
#include "crypto/rsa_private_key.h"
#include "net/cert/x509_util.h"
#include "net/ssl/client_cert_identity_test_util.h"
#include "net/ssl/ssl_private_key.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(ClientCertIdentitySorter, SortClientCertificates) {
  ClientCertIdentityList certs;

  std::unique_ptr<crypto::RSAPrivateKey> key(
      crypto::RSAPrivateKey::Create(1024));
  ASSERT_TRUE(key);

  scoped_refptr<X509Certificate> cert;
  std::string der_cert;

  ASSERT_TRUE(x509_util::CreateSelfSignedCert(
      key.get(), x509_util::DIGEST_SHA1, "CN=expired", 1,
      base::Time::UnixEpoch(), base::Time::UnixEpoch(), &der_cert));
  cert = X509Certificate::CreateFromBytes(der_cert.data(), der_cert.size());
  ASSERT_TRUE(cert);
  certs.push_back(base::MakeUnique<FakeClientCertIdentity>(cert, nullptr));

  const base::Time now = base::Time::Now();

  ASSERT_TRUE(x509_util::CreateSelfSignedCert(
      key.get(), x509_util::DIGEST_SHA1, "CN=not yet valid", 2,
      now + base::TimeDelta::FromDays(10), now + base::TimeDelta::FromDays(15),
      &der_cert));
  cert = X509Certificate::CreateFromBytes(der_cert.data(), der_cert.size());
  ASSERT_TRUE(cert);
  certs.push_back(base::MakeUnique<FakeClientCertIdentity>(cert, nullptr));

  ASSERT_TRUE(x509_util::CreateSelfSignedCert(
      key.get(), x509_util::DIGEST_SHA1, "CN=older cert", 3,
      now - base::TimeDelta::FromDays(5), now + base::TimeDelta::FromDays(5),
      &der_cert));
  cert = X509Certificate::CreateFromBytes(der_cert.data(), der_cert.size());
  ASSERT_TRUE(cert);
  certs.push_back(base::MakeUnique<FakeClientCertIdentity>(cert, nullptr));

  ASSERT_TRUE(x509_util::CreateSelfSignedCert(
      key.get(), x509_util::DIGEST_SHA1, "CN=newer cert", 2,
      now - base::TimeDelta::FromDays(3), now + base::TimeDelta::FromDays(5),
      &der_cert));
  cert = X509Certificate::CreateFromBytes(der_cert.data(), der_cert.size());
  ASSERT_TRUE(cert);
  certs.push_back(base::MakeUnique<FakeClientCertIdentity>(cert, nullptr));

  std::sort(certs.begin(), certs.end(), ClientCertIdentitySorter());

  ASSERT_EQ(4u, certs.size());
  ASSERT_TRUE(certs[0].get());
  EXPECT_EQ("newer cert", certs[0]->certificate()->subject().common_name);
  ASSERT_TRUE(certs[1].get());
  EXPECT_EQ("older cert", certs[1]->certificate()->subject().common_name);
  ASSERT_TRUE(certs[2].get());
  EXPECT_EQ("not yet valid", certs[2]->certificate()->subject().common_name);
  ASSERT_TRUE(certs[3].get());
  EXPECT_EQ("expired", certs[3]->certificate()->subject().common_name);
}

}  // namespace net
