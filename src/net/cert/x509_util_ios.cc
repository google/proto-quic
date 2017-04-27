// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_ios.h"

#include "net/cert/x509_certificate.h"

namespace net {

namespace x509_util {

base::ScopedCFTypeRef<SecCertificateRef>
CreateSecCertificateFromX509Certificate(const X509Certificate* cert) {
  return base::ScopedCFTypeRef<SecCertificateRef>(
      reinterpret_cast<SecCertificateRef>(
          const_cast<void*>(CFRetain(cert->os_cert_handle()))));
}

}  // namespace x509_util

}  // namespace net
