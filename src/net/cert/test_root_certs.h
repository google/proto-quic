// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_TEST_ROOT_CERTS_H_
#define NET_CERT_TEST_ROOT_CERTS_H_

#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "build/build_config.h"
#include "net/base/net_export.h"

#if defined(USE_NSS_CERTS)
#include <cert.h>
#include <vector>
#elif defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
#include <vector>
#elif defined(OS_WIN)
#include <windows.h>
#include "crypto/wincrypt_shim.h"
#elif defined(OS_MACOSX)
#include <CoreFoundation/CFArray.h>
#include <Security/SecTrust.h>
#include "base/mac/scoped_cftyperef.h"
#endif

#if defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
typedef struct x509_st X509;
#endif

namespace base {
class FilePath;
}

namespace net {

class X509Certificate;

// TestRootCerts is a helper class for unit tests that is used to
// artificially mark a certificate as trusted, independent of the local
// machine configuration.
class NET_EXPORT TestRootCerts {
 public:
  // Obtains the Singleton instance to the trusted certificates.
  static TestRootCerts* GetInstance();

  // Returns true if an instance exists, without forcing an initialization.
  static bool HasInstance();

  // Marks |certificate| as trusted for X509Certificate::Verify(). Returns
  // false if the certificate could not be marked trusted.
  bool Add(X509Certificate* certificate);

  // Reads a single certificate from |file| and marks it as trusted. Returns
  // false if an error is encountered, such as being unable to read |file|
  // or more than one certificate existing in |file|.
  bool AddFromFile(const base::FilePath& file);

  // Clears the trusted status of any certificates that were previously
  // marked trusted via Add().
  void Clear();

  // Returns true if there are no certificates that have been marked trusted.
  bool IsEmpty() const;

#if defined(USE_NSS_CERTS)
  bool Contains(CERTCertificate* cert) const;
#elif defined(OS_MACOSX) && !defined(USE_NSS_CERTS)
  CFArrayRef temporary_roots() const { return temporary_roots_; }

  // Modifies the root certificates of |trust_ref| to include the
  // certificates stored in |temporary_roots_|. If IsEmpty() is true, this
  // does not modify |trust_ref|.
  OSStatus FixupSecTrustRef(SecTrustRef trust_ref) const;

  // Configures whether or not the default/system root store should also
  // be trusted. By default, this is true, indicating that the TestRootCerts
  // are used in addition to OS trust store.
  void SetAllowSystemTrust(bool allow_system_trust);
#elif defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
  const std::vector<scoped_refptr<X509Certificate> >&
      temporary_roots() const { return temporary_roots_; }
  bool Contains(X509* cert) const;
#elif defined(OS_WIN)
  HCERTSTORE temporary_roots() const { return temporary_roots_; }

  // Returns an HCERTCHAINENGINE suitable to be used for certificate
  // validation routines, or NULL to indicate that the default system chain
  // engine is appropriate. The caller is responsible for freeing the
  // returned HCERTCHAINENGINE.
  HCERTCHAINENGINE GetChainEngine() const;
#endif

 private:
  friend struct base::DefaultLazyInstanceTraits<TestRootCerts>;

  TestRootCerts();
  ~TestRootCerts();

  // Performs platform-dependent initialization.
  void Init();

#if defined(USE_NSS_CERTS)
  // TrustEntry is used to store the original CERTCertificate and CERTCertTrust
  // for a certificate whose trust status has been changed by the
  // TestRootCerts.
  class TrustEntry {
   public:
    // Creates a new TrustEntry by incrementing the reference to |certificate|
    // and copying |trust|.
    TrustEntry(CERTCertificate* certificate, const CERTCertTrust& trust);
    ~TrustEntry();

    CERTCertificate* certificate() const { return certificate_; }
    const CERTCertTrust& trust() const { return trust_; }

   private:
    // The temporary root certificate.
    CERTCertificate* certificate_;

    // The original trust settings, before |certificate_| was manipulated to
    // be a temporarily trusted root.
    CERTCertTrust trust_;

    DISALLOW_COPY_AND_ASSIGN(TrustEntry);
  };

  // It is necessary to maintain a cache of the original certificate trust
  // settings, in order to restore them when Clear() is called.
  std::vector<std::unique_ptr<TrustEntry>> trust_cache_;
#elif defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
  std::vector<scoped_refptr<X509Certificate>> temporary_roots_;
#elif defined(OS_WIN)
  HCERTSTORE temporary_roots_;
#elif defined(OS_MACOSX)
  base::ScopedCFTypeRef<CFMutableArrayRef> temporary_roots_;
  bool allow_system_trust_;
#endif

#if defined(OS_WIN) || defined(OS_ANDROID)
  // True if there are no temporarily trusted root certificates.
  bool empty_;
#endif

  DISALLOW_COPY_AND_ASSIGN(TestRootCerts);
};

// Scoped helper for unittests to handle safely managing trusted roots.
class NET_EXPORT_PRIVATE ScopedTestRoot {
 public:
  ScopedTestRoot();
  // Creates a ScopedTestRoot that will add |cert| to the TestRootCerts store.
  explicit ScopedTestRoot(X509Certificate* cert);
  ~ScopedTestRoot();

  // Assigns |cert| to be the new test root cert. If |cert| is NULL, undoes
  // any work the ScopedTestRoot may have previously done.
  // If |cert_| contains a certificate (due to a prior call to Reset or due to
  // a cert being passed at construction), the existing TestRootCerts store is
  // cleared.
  void Reset(X509Certificate* cert);

 private:
  scoped_refptr<X509Certificate> cert_;

  DISALLOW_COPY_AND_ASSIGN(ScopedTestRoot);
};

}  // namespace net

#endif  // NET_CERT_TEST_ROOT_CERTS_H_
