// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/test_root_certs.h"

#include "base/location.h"
#include "base/logging.h"
#include "crypto/openssl_util.h"
#include "net/cert/x509_certificate.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace net {

bool TestRootCerts::Add(X509Certificate* certificate) {
  if (!X509_STORE_add_cert(X509Certificate::cert_store(),
                           certificate->os_cert_handle())) {
    uint32_t error_code = ERR_peek_error();
    if (ERR_GET_LIB(error_code) != ERR_LIB_X509 ||
        ERR_GET_REASON(error_code) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
      crypto::ClearOpenSSLERRStack(FROM_HERE);
      return false;
    }
    ERR_clear_error();
  }

  temporary_roots_.push_back(certificate);
  return true;
}

void TestRootCerts::Clear() {
  if (temporary_roots_.empty())
    return;

  temporary_roots_.clear();
  X509Certificate::ResetCertStore();
}

bool TestRootCerts::IsEmpty() const {
  return temporary_roots_.empty();
}

bool TestRootCerts::Contains(X509* cert) const {
  for (std::vector<scoped_refptr<X509Certificate> >::const_iterator it =
           temporary_roots_.begin();
       it != temporary_roots_.end(); ++it) {
    if (X509Certificate::IsSameOSCert(cert, (*it)->os_cert_handle()))
      return true;
  }
  return false;
}

TestRootCerts::~TestRootCerts() {}

void TestRootCerts::Init() {}

}  // namespace net
