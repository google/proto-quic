// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_ios_and_mac.h"

#include "net/cert/x509_certificate.h"
#if defined(OS_IOS)
#include "net/cert/x509_util_ios.h"
#else
#include "net/cert/x509_util_mac.h"
#endif
#include "third_party/boringssl/src/include/openssl/pool.h"

namespace net {

namespace x509_util {

base::ScopedCFTypeRef<CFMutableArrayRef>
CreateSecCertificateArrayForX509Certificate(X509Certificate* cert) {
  base::ScopedCFTypeRef<CFMutableArrayRef> cert_list(
      CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
  if (!cert_list)
    return base::ScopedCFTypeRef<CFMutableArrayRef>();
#if BUILDFLAG(USE_BYTE_CERTS)
  std::string bytes;
  base::ScopedCFTypeRef<SecCertificateRef> sec_cert(
      CreateSecCertificateFromBytes(CRYPTO_BUFFER_data(cert->os_cert_handle()),
                                    CRYPTO_BUFFER_len(cert->os_cert_handle())));
  if (!sec_cert)
    return base::ScopedCFTypeRef<CFMutableArrayRef>();
  CFArrayAppendValue(cert_list, sec_cert);
  for (X509Certificate::OSCertHandle intermediate :
       cert->GetIntermediateCertificates()) {
    base::ScopedCFTypeRef<SecCertificateRef> sec_cert(
        CreateSecCertificateFromBytes(CRYPTO_BUFFER_data(intermediate),
                                      CRYPTO_BUFFER_len(intermediate)));
    if (!sec_cert)
      return base::ScopedCFTypeRef<CFMutableArrayRef>();
    CFArrayAppendValue(cert_list, sec_cert);
  }
#else
  X509Certificate::OSCertHandles intermediate_ca_certs =
      cert->GetIntermediateCertificates();
  CFArrayAppendValue(cert_list, cert->os_cert_handle());
  for (size_t i = 0; i < intermediate_ca_certs.size(); ++i)
    CFArrayAppendValue(cert_list, intermediate_ca_certs[i]);
#endif
  return cert_list;
}

}  // namespace x509_util

}  // namespace net
