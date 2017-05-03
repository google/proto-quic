// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/system_trust_store.h"

#if defined(USE_NSS_CERTS)
#include <cert.h>
#include <pk11pub.h>
#elif defined(OS_MACOSX) && !defined(OS_IOS)
#include <Security/Security.h>
#endif

#include "base/memory/ptr_util.h"
#include "net/cert/internal/trust_store_collection.h"
#include "net/cert/internal/trust_store_in_memory.h"

#if defined(USE_NSS_CERTS)
#include "crypto/nss_util.h"
#include "net/cert/internal/trust_store_nss.h"
#include "net/cert/known_roots_nss.h"
#include "net/cert/scoped_nss_types.h"
#elif defined(OS_MACOSX) && !defined(OS_IOS)
#include "net/cert/internal/trust_store_mac.h"
#include "net/cert/known_roots_mac.h"
#include "net/cert/x509_util_mac.h"
#endif

namespace net {

namespace {

// Abstract implementation of SystemTrustStore to be used as a base class.
// Handles the addition of additional trust anchors.
class BaseSystemTrustStore : public SystemTrustStore {
 public:
  BaseSystemTrustStore() {
    trust_store_.AddTrustStore(&additional_trust_store_);
  }

  void AddTrustAnchor(
      const scoped_refptr<ParsedCertificate>& trust_anchor) override {
    additional_trust_store_.AddTrustAnchor(trust_anchor);
  }

  TrustStore* GetTrustStore() override { return &trust_store_; }

  bool IsAdditionalTrustAnchor(
      const ParsedCertificate* trust_anchor) const override {
    return additional_trust_store_.Contains(trust_anchor);
  }

 protected:
  TrustStoreCollection trust_store_;
  TrustStoreInMemory additional_trust_store_;
};

}  // namespace

#if defined(USE_NSS_CERTS)
namespace {

class SystemTrustStoreNSS : public BaseSystemTrustStore {
 public:
  explicit SystemTrustStoreNSS() : trust_store_nss_(trustSSL) {
    trust_store_.AddTrustStore(&trust_store_nss_);
  }

  bool UsesSystemTrustStore() const override { return true; }

  // IsKnownRoot returns true if the given trust anchor is a standard one (as
  // opposed to a user-installed root)
  bool IsKnownRoot(const ParsedCertificate* trust_anchor) const override {
    // TODO(eroman): The overall approach of IsKnownRoot() is inefficient -- it
    // requires searching for the trust anchor by DER in NSS, however path
    // building already had a handle to it.
    SECItem der_cert;
    der_cert.data = const_cast<uint8_t*>(trust_anchor->der_cert().UnsafeData());
    der_cert.len = trust_anchor->der_cert().Length();
    der_cert.type = siDERCertBuffer;
    ScopedCERTCertificate nss_cert(
        CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &der_cert));
    if (!nss_cert)
      return false;

    if (!net::IsKnownRoot(nss_cert.get()))
      return false;

    return trust_anchor->der_cert() ==
           der::Input(nss_cert->derCert.data, nss_cert->derCert.len);
  }

 private:
  TrustStoreNSS trust_store_nss_;
};

}  // namespace

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStore() {
  return base::MakeUnique<SystemTrustStoreNSS>();
}

#elif defined(OS_MACOSX) && !defined(OS_IOS)

// TODO(eroman): Compose with test roots added via cert/test_roots.h
class SystemTrustStoreMac : public BaseSystemTrustStore {
 public:
  explicit SystemTrustStoreMac() : trust_store_mac_(kSecPolicyAppleSSL) {
    InitializeKnownRoots();
    trust_store_.AddTrustStore(&trust_store_mac_);
  }

  bool UsesSystemTrustStore() const override { return true; }

  // IsKnownRoot returns true if the given trust anchor is a standard one (as
  // opposed to a user-installed root)
  bool IsKnownRoot(const ParsedCertificate* trust_anchor) const override {
    der::Input bytes = trust_anchor->der_cert();
    base::ScopedCFTypeRef<SecCertificateRef> cert_ref =
        x509_util::CreateSecCertificateFromBytes(bytes.UnsafeData(),
                                                 bytes.Length());
    if (!cert_ref)
      return false;

    return net::IsKnownRoot(cert_ref);
  }

 private:
  TrustStoreMac trust_store_mac_;
};

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStore() {
  return base::MakeUnique<SystemTrustStoreMac>();
}
#else

class DummySystemTrustStore : public BaseSystemTrustStore {
 public:
  bool UsesSystemTrustStore() const override { return false; }

  bool IsKnownRoot(const ParsedCertificate* trust_anchor) const override {
    return false;
  }
};

std::unique_ptr<SystemTrustStore> CreateSslSystemTrustStore() {
  return base::MakeUnique<DummySystemTrustStore>();
}
#endif

}  // namespace net
