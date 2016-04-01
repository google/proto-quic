// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/test_root_certs.h"

#include <Security/Security.h>

#include "base/logging.h"
#include "net/cert/x509_certificate.h"

namespace net {

namespace {

typedef OSStatus (*SecTrustSetAnchorCertificatesOnlyFuncPtr)(SecTrustRef,
                                                             Boolean);

Boolean OurSecCertificateEqual(const void* value1, const void* value2) {
  if (CFGetTypeID(value1) != SecCertificateGetTypeID() ||
      CFGetTypeID(value2) != SecCertificateGetTypeID())
    return CFEqual(value1, value2);
  return X509Certificate::IsSameOSCert(
      reinterpret_cast<SecCertificateRef>(const_cast<void*>(value1)),
      reinterpret_cast<SecCertificateRef>(const_cast<void*>(value2)));
}

const void* RetainWrapper(CFAllocatorRef unused, const void* value) {
  return CFRetain(value);
}

void ReleaseWrapper(CFAllocatorRef unused, const void* value) {
  CFRelease(value);
}

// CFEqual prior to 10.6 only performed pointer checks on SecCertificateRefs,
// rather than checking if they were the same (logical) certificate, so a
// custom structure is used for the array callbacks.
const CFArrayCallBacks kCertArrayCallbacks = {
  0,  // version
  RetainWrapper,
  ReleaseWrapper,
  CFCopyDescription,
  OurSecCertificateEqual,
};

}  // namespace

bool TestRootCerts::Add(X509Certificate* certificate) {
  if (CFArrayContainsValue(temporary_roots_,
                           CFRangeMake(0, CFArrayGetCount(temporary_roots_)),
                           certificate->os_cert_handle()))
    return true;
  CFArrayAppendValue(temporary_roots_, certificate->os_cert_handle());
  return true;
}

void TestRootCerts::Clear() {
  CFArrayRemoveAllValues(temporary_roots_);
}

bool TestRootCerts::IsEmpty() const {
  return CFArrayGetCount(temporary_roots_) == 0;
}

OSStatus TestRootCerts::FixupSecTrustRef(SecTrustRef trust_ref) const {
  if (IsEmpty())
    return noErr;

  OSStatus status = SecTrustSetAnchorCertificates(trust_ref, temporary_roots_);
  if (status)
    return status;
  return SecTrustSetAnchorCertificatesOnly(trust_ref, !allow_system_trust_);
}

void TestRootCerts::SetAllowSystemTrust(bool allow_system_trust) {
  allow_system_trust_ = allow_system_trust;
}

TestRootCerts::~TestRootCerts() {}

void TestRootCerts::Init() {
  temporary_roots_.reset(CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                              &kCertArrayCallbacks));
  allow_system_trust_ = true;
}

}  // namespace net
