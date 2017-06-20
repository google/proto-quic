// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_identity_test_util.h"

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/test_ssl_private_key.h"
#include "net/test/cert_test_util.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/evp.h"

namespace net {

FakeClientCertIdentity::FakeClientCertIdentity(
    scoped_refptr<X509Certificate> cert,
    scoped_refptr<SSLPrivateKey> key)
    : ClientCertIdentity(std::move(cert)), key_(std::move(key)) {}

FakeClientCertIdentity::~FakeClientCertIdentity() = default;

// static
std::unique_ptr<FakeClientCertIdentity>
FakeClientCertIdentity::CreateFromCertAndKeyFiles(
    const base::FilePath& dir,
    const std::string& cert_filename,
    const std::string& key_filename) {
  scoped_refptr<X509Certificate> cert =
      net::ImportCertFromFile(dir, cert_filename);
  if (!cert)
    return nullptr;

  std::string pkcs8;
  if (!base::ReadFileToString(dir.AppendASCII(key_filename), &pkcs8))
    return nullptr;

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(pkcs8.data()), pkcs8.size());
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_private_key(&cbs));
  if (!pkey || CBS_len(&cbs) != 0)
    return nullptr;

  scoped_refptr<SSLPrivateKey> ssl_private_key =
      WrapOpenSSLPrivateKey(std::move(pkey));
  if (!ssl_private_key)
    return nullptr;

  return base::MakeUnique<FakeClientCertIdentity>(cert, ssl_private_key);
}

std::unique_ptr<FakeClientCertIdentity> FakeClientCertIdentity::Copy() {
  return base::MakeUnique<FakeClientCertIdentity>(certificate(), key_);
}

void FakeClientCertIdentity::AcquirePrivateKey(
    const base::Callback<void(scoped_refptr<SSLPrivateKey>)>&
        private_key_callback) {
  private_key_callback.Run(key_);
}

#if defined(OS_MACOSX)
SecIdentityRef FakeClientCertIdentity::sec_identity_ref() const {
  // Any tests that depend on having a real SecIdentityRef should use a real
  // ClientCertIdentityMac.
  NOTREACHED();
  return nullptr;
}
#endif

ClientCertIdentityList FakeClientCertIdentityListFromCertificateList(
    const CertificateList& certs) {
  ClientCertIdentityList result;
  for (const auto& cert : certs) {
    result.push_back(base::MakeUnique<FakeClientCertIdentity>(cert, nullptr));
  }
  return result;
}

}  // namespace net
