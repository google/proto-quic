// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_X509_UTIL_WIN_H_
#define NET_CERT_X509_UTIL_WIN_H_

#include <memory>
#include <vector>

#include <windows.h>

#include "base/memory/ref_counted.h"
#include "crypto/wincrypt_shim.h"
#include "net/base/hash_value.h"
#include "net/base/net_export.h"

namespace net {

class X509Certificate;

struct FreeCertContextFunctor {
  void operator()(PCCERT_CONTEXT context) const {
    if (context)
      CertFreeCertificateContext(context);
  }
};

using ScopedPCCERT_CONTEXT =
    std::unique_ptr<const CERT_CONTEXT, FreeCertContextFunctor>;

namespace x509_util {

// Creates an X509Certificate representing |os_cert| with intermediates
// |os_chain|.
NET_EXPORT scoped_refptr<X509Certificate> CreateX509CertificateFromCertContexts(
    PCCERT_CONTEXT os_cert,
    const std::vector<PCCERT_CONTEXT>& os_chain);

// Returns a new PCCERT_CONTEXT containing the certificate and its
// intermediate certificates, or NULL on failure. This function is only
// necessary if the CERT_CONTEXT.hCertStore member will be accessed or
// enumerated, which is generally true for any CryptoAPI functions involving
// certificate chains, including validation or certificate display.
//
// While the returned PCCERT_CONTEXT and its HCERTSTORE can safely be used on
// multiple threads if no further modifications happen, it is generally
// preferable for each thread that needs such a context to obtain its own,
// rather than risk thread-safety issues by sharing.
//
// ------------------------------------------------------------------------
// The following remarks only apply when USE_BYTE_CERTS=false (e.g., when
// using x509_certificate_win).
// TODO(mattm): remove references to USE_BYTE_CERTS and clean up the rest of
// the comment when x509_certificate_win is deleted.
//
// The returned PCCERT_CONTEXT *MUST NOT* be stored in an X509Certificate, as
// this will cause os_cert_handle() to return incorrect results.
//
// Depending on the CryptoAPI function, Windows may need to access the
// HCERTSTORE that the passed-in PCCERT_CONTEXT belongs to, such as to
// locate additional intermediates. However, all X509Certificate handles are
// added to a NULL HCERTSTORE, allowing the system to manage the resources.  As
// a result, intermediates for |cert->os_cert_handle()| cannot be located
// simply via |cert->os_cert_handle()->hCertStore|, as it refers to a magic
// value indicating "only this certificate".
//
// To avoid this problems, a new in-memory HCERTSTORE is created containing
// just this certificate and its intermediates. The handle to the version of
// the current certificate in the new HCERTSTORE is then returned, with the
// PCCERT_CONTEXT's HCERTSTORE set to be automatically freed when the returned
// certificate handle is freed.
//
// Because of how X509Certificate caching is implemented, attempting to
// create an X509Certificate from the returned PCCERT_CONTEXT may result in
// the original handle (and thus the originall HCERTSTORE) being returned by
// os_cert_handle(). For this reason, the returned PCCERT_CONTEXT *MUST NOT*
// be stored in an X509Certificate.
NET_EXPORT ScopedPCCERT_CONTEXT
CreateCertContextWithChain(const X509Certificate* cert);

// Calculates the SHA-256 fingerprint of the certificate.  Returns an empty
// (all zero) fingerprint on failure.
NET_EXPORT SHA256HashValue CalculateFingerprint256(PCCERT_CONTEXT cert);

// Returns true if the certificate is self-signed.
NET_EXPORT bool IsSelfSigned(PCCERT_CONTEXT cert_handle);

}  // namespace x509_util

}  // namespace net

#endif  // NET_CERT_X509_UTIL_WIN_H_
