// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_mac.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include <set>
#include <string>
#include <vector>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/mac/mac_logging.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/sha1.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "crypto/mac_security_services_lock.h"
#include "crypto/sha2.h"
#include "net/base/hash_value.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_mac.h"

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// From 10.7.2 libsecurity_keychain-55035/lib/SecTrustPriv.h, for use with
// SecTrustCopyExtendedResult.
#ifndef kSecEVOrganizationName
#define kSecEVOrganizationName CFSTR("Organization")
#endif

using base::ScopedCFTypeRef;

namespace net {

namespace {

typedef OSStatus (*SecTrustCopyExtendedResultFuncPtr)(SecTrustRef,
                                                      CFDictionaryRef*);

int NetErrorFromOSStatus(OSStatus status) {
  switch (status) {
    case noErr:
      return OK;
    case errSecNotAvailable:
    case errSecNoCertificateModule:
    case errSecNoPolicyModule:
      return ERR_NOT_IMPLEMENTED;
    case errSecAuthFailed:
      return ERR_ACCESS_DENIED;
    default: {
      OSSTATUS_LOG(ERROR, status) << "Unknown error mapped to ERR_FAILED";
      return ERR_FAILED;
    }
  }
}

CertStatus CertStatusFromOSStatus(OSStatus status) {
  switch (status) {
    case noErr:
      return 0;

    case CSSMERR_TP_INVALID_ANCHOR_CERT:
    case CSSMERR_TP_NOT_TRUSTED:
    case CSSMERR_TP_INVALID_CERT_AUTHORITY:
      return CERT_STATUS_AUTHORITY_INVALID;

    case CSSMERR_TP_CERT_EXPIRED:
    case CSSMERR_TP_CERT_NOT_VALID_YET:
      // "Expired" and "not yet valid" collapse into a single status.
      return CERT_STATUS_DATE_INVALID;

    case CSSMERR_TP_CERT_REVOKED:
    case CSSMERR_TP_CERT_SUSPENDED:
      return CERT_STATUS_REVOKED;

    case CSSMERR_APPLETP_HOSTNAME_MISMATCH:
      return CERT_STATUS_COMMON_NAME_INVALID;

    case CSSMERR_APPLETP_CRL_NOT_FOUND:
    case CSSMERR_APPLETP_OCSP_UNAVAILABLE:
    case CSSMERR_APPLETP_INCOMPLETE_REVOCATION_CHECK:
      return CERT_STATUS_NO_REVOCATION_MECHANISM;

    case CSSMERR_APPLETP_CRL_EXPIRED:
    case CSSMERR_APPLETP_CRL_NOT_VALID_YET:
    case CSSMERR_APPLETP_CRL_SERVER_DOWN:
    case CSSMERR_APPLETP_CRL_NOT_TRUSTED:
    case CSSMERR_APPLETP_CRL_INVALID_ANCHOR_CERT:
    case CSSMERR_APPLETP_CRL_POLICY_FAIL:
    case CSSMERR_APPLETP_OCSP_BAD_RESPONSE:
    case CSSMERR_APPLETP_OCSP_BAD_REQUEST:
    case CSSMERR_APPLETP_OCSP_STATUS_UNRECOGNIZED:
    case CSSMERR_APPLETP_NETWORK_FAILURE:
    case CSSMERR_APPLETP_OCSP_NOT_TRUSTED:
    case CSSMERR_APPLETP_OCSP_INVALID_ANCHOR_CERT:
    case CSSMERR_APPLETP_OCSP_SIG_ERROR:
    case CSSMERR_APPLETP_OCSP_NO_SIGNER:
    case CSSMERR_APPLETP_OCSP_RESP_MALFORMED_REQ:
    case CSSMERR_APPLETP_OCSP_RESP_INTERNAL_ERR:
    case CSSMERR_APPLETP_OCSP_RESP_TRY_LATER:
    case CSSMERR_APPLETP_OCSP_RESP_SIG_REQUIRED:
    case CSSMERR_APPLETP_OCSP_RESP_UNAUTHORIZED:
    case CSSMERR_APPLETP_OCSP_NONCE_MISMATCH:
      // We asked for a revocation check, but didn't get it.
      return CERT_STATUS_UNABLE_TO_CHECK_REVOCATION;

    case CSSMERR_APPLETP_SSL_BAD_EXT_KEY_USE:
      // TODO(wtc): Should we add CERT_STATUS_WRONG_USAGE?
      return CERT_STATUS_INVALID;

    case CSSMERR_APPLETP_CRL_BAD_URI:
    case CSSMERR_APPLETP_IDP_FAIL:
      return CERT_STATUS_INVALID;

    case CSSMERR_CSP_UNSUPPORTED_KEY_SIZE:
      // Mapping UNSUPPORTED_KEY_SIZE to CERT_STATUS_WEAK_KEY is not strictly
      // accurate, as the error may have been returned due to a key size
      // that exceeded the maximum supported. However, within
      // CertVerifyProcMac::VerifyInternal(), this code should only be
      // encountered as a certificate status code, and only when the key size
      // is smaller than the minimum required (1024 bits).
      return CERT_STATUS_WEAK_KEY;

    default: {
      // Failure was due to something Chromium doesn't define a
      // specific status for (such as basic constraints violation, or
      // unknown critical extension)
      OSSTATUS_LOG(WARNING, status)
          << "Unknown error mapped to CERT_STATUS_INVALID";
      return CERT_STATUS_INVALID;
    }
  }
}

// Creates a series of SecPolicyRefs to be added to a SecTrustRef used to
// validate a certificate for an SSL server. |hostname| contains the name of
// the SSL server that the certificate should be verified against. |flags| is
// a bitwise-OR of VerifyFlags that can further alter how trust is validated,
// such as how revocation is checked. If successful, returns noErr, and
// stores the resultant array of SecPolicyRefs in |policies|.
OSStatus CreateTrustPolicies(const std::string& hostname,
                             int flags,
                             ScopedCFTypeRef<CFArrayRef>* policies) {
  ScopedCFTypeRef<CFMutableArrayRef> local_policies(
      CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
  if (!local_policies)
    return memFullErr;

  SecPolicyRef ssl_policy;
  OSStatus status = x509_util::CreateSSLServerPolicy(hostname, &ssl_policy);
  if (status)
    return status;
  CFArrayAppendValue(local_policies, ssl_policy);
  CFRelease(ssl_policy);

  // Explicitly add revocation policies, in order to override system
  // revocation checking policies and instead respect the application-level
  // revocation preference.
  status = x509_util::CreateRevocationPolicies(
      (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED),
      (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED_EV_ONLY),
      local_policies);
  if (status)
    return status;

  policies->reset(local_policies.release());
  return noErr;
}

// Stores the constructed certificate chain |cert_chain| and information about
// the signature algorithms used into |*verify_result|. If the leaf cert in
// |cert_chain| contains a weak (MD2, MD4, MD5, SHA-1) signature, stores that
// in |*leaf_is_weak|. |cert_chain| must not be empty.
void GetCertChainInfo(CFArrayRef cert_chain,
                      CSSM_TP_APPLE_EVIDENCE_INFO* chain_info,
                      CertVerifyResult* verify_result,
                      bool* leaf_is_weak) {
  DCHECK_LT(0, CFArrayGetCount(cert_chain));

  *leaf_is_weak = false;
  verify_result->has_md2 = false;
  verify_result->has_md4 = false;
  verify_result->has_md5 = false;
  verify_result->has_sha1 = false;
  verify_result->has_sha1_leaf = false;

  SecCertificateRef verified_cert = NULL;
  std::vector<SecCertificateRef> verified_chain;
  for (CFIndex i = 0, count = CFArrayGetCount(cert_chain); i < count; ++i) {
    SecCertificateRef chain_cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(cert_chain, i)));
    if (i == 0) {
      verified_cert = chain_cert;
    } else {
      verified_chain.push_back(chain_cert);
    }

    if ((chain_info[i].StatusBits & CSSM_CERT_STATUS_IS_IN_ANCHORS) ||
        (chain_info[i].StatusBits & CSSM_CERT_STATUS_IS_ROOT)) {
      // The current certificate is either in the user's trusted store or is
      // a root (self-signed) certificate. Ignore the signature algorithm for
      // these certificates, as it is meaningless for security. We allow
      // self-signed certificates (i == 0 & IS_ROOT), since we accept that
      // any security assertions by such a cert are inherently meaningless.
      continue;
    }

    x509_util::CSSMCachedCertificate cached_cert;
    OSStatus status = cached_cert.Init(chain_cert);
    if (status)
      continue;
    x509_util::CSSMFieldValue signature_field;
    status = cached_cert.GetField(&CSSMOID_X509V1SignatureAlgorithm,
                                  &signature_field);
    if (status || !signature_field.field())
      continue;
    // Match the behaviour of OS X system tools and defensively check that
    // sizes are appropriate. This would indicate a critical failure of the
    // OS X certificate library, but based on history, it is best to play it
    // safe.
    const CSSM_X509_ALGORITHM_IDENTIFIER* sig_algorithm =
        signature_field.GetAs<CSSM_X509_ALGORITHM_IDENTIFIER>();
    if (!sig_algorithm)
      continue;

    const CSSM_OID* alg_oid = &sig_algorithm->algorithm;
    if (CSSMOIDEqual(alg_oid, &CSSMOID_MD2WithRSA)) {
      verify_result->has_md2 = true;
      if (i == 0)
        *leaf_is_weak = true;
    } else if (CSSMOIDEqual(alg_oid, &CSSMOID_MD4WithRSA)) {
      verify_result->has_md4 = true;
      if (i == 0)
        *leaf_is_weak = true;
    } else if (CSSMOIDEqual(alg_oid, &CSSMOID_MD5WithRSA)) {
      verify_result->has_md5 = true;
      if (i == 0)
        *leaf_is_weak = true;
    } else if (CSSMOIDEqual(alg_oid, &CSSMOID_SHA1WithRSA) ||
               CSSMOIDEqual(alg_oid, &CSSMOID_SHA1WithRSA_OIW) ||
               CSSMOIDEqual(alg_oid, &CSSMOID_SHA1WithDSA) ||
               CSSMOIDEqual(alg_oid, &CSSMOID_SHA1WithDSA_CMS) ||
               CSSMOIDEqual(alg_oid, &CSSMOID_SHA1WithDSA_JDK) ||
               CSSMOIDEqual(alg_oid, &CSSMOID_ECDSA_WithSHA1)) {
      verify_result->has_sha1 = true;
      if (i == 0) {
        verify_result->has_sha1_leaf = true;
        *leaf_is_weak = true;
      }
    }
  }
  if (!verified_cert) {
    NOTREACHED();
    return;
  }

  verify_result->verified_cert =
      X509Certificate::CreateFromHandle(verified_cert, verified_chain);
}

void AppendPublicKeyHashes(CFArrayRef chain,
                           HashValueVector* hashes) {
  const CFIndex n = CFArrayGetCount(chain);
  for (CFIndex i = 0; i < n; i++) {
    SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(chain, i)));

    CSSM_DATA cert_data;
    OSStatus err = SecCertificateGetData(cert, &cert_data);
    DCHECK_EQ(err, noErr);
    base::StringPiece der_bytes(reinterpret_cast<const char*>(cert_data.Data),
                               cert_data.Length);
    base::StringPiece spki_bytes;
    if (!asn1::ExtractSPKIFromDERCert(der_bytes, &spki_bytes))
      continue;

    HashValue sha1(HASH_VALUE_SHA1);
    CC_SHA1(spki_bytes.data(), spki_bytes.size(), sha1.data());
    hashes->push_back(sha1);

    HashValue sha256(HASH_VALUE_SHA256);
    CC_SHA256(spki_bytes.data(), spki_bytes.size(), sha256.data());
    hashes->push_back(sha256);
  }
}

bool CheckRevocationWithCRLSet(CFArrayRef chain, CRLSet* crl_set) {
  if (CFArrayGetCount(chain) == 0)
    return true;

  // We iterate from the root certificate down to the leaf, keeping track of
  // the issuer's SPKI at each step.
  std::string issuer_spki_hash;
  for (CFIndex i = CFArrayGetCount(chain) - 1; i >= 0; i--) {
    SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(chain, i)));

    CSSM_DATA cert_data;
    OSStatus err = SecCertificateGetData(cert, &cert_data);
    if (err != noErr) {
      NOTREACHED();
      continue;
    }
    base::StringPiece der_bytes(reinterpret_cast<const char*>(cert_data.Data),
                                cert_data.Length);
    base::StringPiece spki;
    if (!asn1::ExtractSPKIFromDERCert(der_bytes, &spki)) {
      NOTREACHED();
      continue;
    }

    const std::string spki_hash = crypto::SHA256HashString(spki);
    x509_util::CSSMCachedCertificate cached_cert;
    if (cached_cert.Init(cert) != CSSM_OK) {
      NOTREACHED();
      continue;
    }
    x509_util::CSSMFieldValue serial_number;
    err = cached_cert.GetField(&CSSMOID_X509V1SerialNumber, &serial_number);
    if (err || !serial_number.field()) {
      NOTREACHED();
      continue;
    }

    base::StringPiece serial(
        reinterpret_cast<const char*>(serial_number.field()->Data),
        serial_number.field()->Length);

    CRLSet::Result result = crl_set->CheckSPKI(spki_hash);

    if (result != CRLSet::REVOKED && !issuer_spki_hash.empty())
      result = crl_set->CheckSerial(serial, issuer_spki_hash);

    issuer_spki_hash = spki_hash;

    switch (result) {
      case CRLSet::REVOKED:
        return false;
      case CRLSet::UNKNOWN:
      case CRLSet::GOOD:
        continue;
      default:
        NOTREACHED();
        return false;
    }
  }

  return true;
}

// Builds and evaluates a SecTrustRef for the certificate chain contained
// in |cert_array|, using the verification policies in |trust_policies|. On
// success, returns OK, and updates |trust_ref|, |trust_result|,
// |verified_chain|, and |chain_info| with the verification results. On
// failure, no output parameters are modified.
//
// Note: An OK return does not mean that |cert_array| is trusted, merely that
// verification was performed successfully.
//
// This function should only be called while the Mac Security Services lock is
// held.
int BuildAndEvaluateSecTrustRef(CFArrayRef cert_array,
                                CFArrayRef trust_policies,
                                int flags,
                                ScopedCFTypeRef<SecTrustRef>* trust_ref,
                                SecTrustResultType* trust_result,
                                ScopedCFTypeRef<CFArrayRef>* verified_chain,
                                CSSM_TP_APPLE_EVIDENCE_INFO** chain_info) {
  SecTrustRef tmp_trust = NULL;
  OSStatus status = SecTrustCreateWithCertificates(cert_array, trust_policies,
                                                   &tmp_trust);
  if (status)
    return NetErrorFromOSStatus(status);
  ScopedCFTypeRef<SecTrustRef> scoped_tmp_trust(tmp_trust);

  if (TestRootCerts::HasInstance()) {
    status = TestRootCerts::GetInstance()->FixupSecTrustRef(tmp_trust);
    if (status)
      return NetErrorFromOSStatus(status);
  }

  CSSM_APPLE_TP_ACTION_DATA tp_action_data;
  memset(&tp_action_data, 0, sizeof(tp_action_data));
  tp_action_data.Version = CSSM_APPLE_TP_ACTION_VERSION;
  // Allow CSSM to download any missing intermediate certificates if an
  // authorityInfoAccess extension or issuerAltName extension is present.
  tp_action_data.ActionFlags = CSSM_TP_ACTION_FETCH_CERT_FROM_NET |
                               CSSM_TP_ACTION_TRUST_SETTINGS;

  // Note: For EV certificates, the Apple TP will handle setting these flags
  // as part of EV evaluation.
  if (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED) {
    // Require a positive result from an OCSP responder or a CRL (or both)
    // for every certificate in the chain. The Apple TP automatically
    // excludes the self-signed root from this requirement. If a certificate
    // is missing both a crlDistributionPoints extension and an
    // authorityInfoAccess extension with an OCSP responder URL, then we
    // will get a kSecTrustResultRecoverableTrustFailure back from
    // SecTrustEvaluate(), with a
    // CSSMERR_APPLETP_INCOMPLETE_REVOCATION_CHECK error code. In that case,
    // we'll set our own result to include
    // CERT_STATUS_NO_REVOCATION_MECHANISM. If one or both extensions are
    // present, and a check fails (server unavailable, OCSP retry later,
    // signature mismatch), then we'll set our own result to include
    // CERT_STATUS_UNABLE_TO_CHECK_REVOCATION.
    tp_action_data.ActionFlags |= CSSM_TP_ACTION_REQUIRE_REV_PER_CERT;

    // Note, even if revocation checking is disabled, SecTrustEvaluate() will
    // modify the OCSP options so as to attempt OCSP checking if it believes a
    // certificate may chain to an EV root. However, because network fetches
    // are disabled in CreateTrustPolicies() when revocation checking is
    // disabled, these will only go against the local cache.
  }

  CFDataRef action_data_ref =
      CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                  reinterpret_cast<UInt8*>(&tp_action_data),
                                  sizeof(tp_action_data), kCFAllocatorNull);
  if (!action_data_ref)
    return ERR_OUT_OF_MEMORY;
  ScopedCFTypeRef<CFDataRef> scoped_action_data_ref(action_data_ref);
  status = SecTrustSetParameters(tmp_trust, CSSM_TP_ACTION_DEFAULT,
                                 action_data_ref);
  if (status)
    return NetErrorFromOSStatus(status);

  // Verify the certificate. A non-zero result from SecTrustGetResult()
  // indicates that some fatal error occurred and the chain couldn't be
  // processed, not that the chain contains no errors. We need to examine the
  // output of SecTrustGetResult() to determine that.
  SecTrustResultType tmp_trust_result;
  status = SecTrustEvaluate(tmp_trust, &tmp_trust_result);
  if (status)
    return NetErrorFromOSStatus(status);
  CFArrayRef tmp_verified_chain = NULL;
  CSSM_TP_APPLE_EVIDENCE_INFO* tmp_chain_info;
  status = SecTrustGetResult(tmp_trust, &tmp_trust_result, &tmp_verified_chain,
                             &tmp_chain_info);
  if (status)
    return NetErrorFromOSStatus(status);

  trust_ref->swap(scoped_tmp_trust);
  *trust_result = tmp_trust_result;
  verified_chain->reset(tmp_verified_chain);
  *chain_info = tmp_chain_info;

  return OK;
}

// Helper class for managing the set of OS X Known Roots. This is only safe
// to initialize while the crypto::GetMacSecurityServicesLock() is held, due
// to calling into Security.framework functions; however, once initialized,
// it can be called at any time.
// In practice, due to lazy initialization, it's best to just always guard
// accesses with the lock.
class OSXKnownRootHelper {
 public:
  // IsIssuedByKnownRoot returns true if the given chain is rooted at a root CA
  // that we recognise as a standard root.
  bool IsIssuedByKnownRoot(CFArrayRef chain) {
    // If there are no known roots, then an API failure occurred. For safety,
    // assume that all certificates are issued by known roots.
    if (known_roots_.empty())
      return true;

    CFIndex n = CFArrayGetCount(chain);
    if (n < 1)
      return false;
    SecCertificateRef root_ref = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(chain, n - 1)));
    SHA256HashValue hash = X509Certificate::CalculateFingerprint256(root_ref);
    return known_roots_.find(hash) != known_roots_.end();
  }

 private:
  friend struct base::DefaultLazyInstanceTraits<OSXKnownRootHelper>;

  OSXKnownRootHelper() {
    CFArrayRef cert_array = NULL;
    OSStatus rv = SecTrustSettingsCopyCertificates(
        kSecTrustSettingsDomainSystem, &cert_array);
    if (rv != noErr) {
      LOG(ERROR) << "Unable to determine trusted roots; assuming all roots are "
                 << "trusted! Error " << rv;
      return;
    }
    base::ScopedCFTypeRef<CFArrayRef> scoped_array(cert_array);
    for (CFIndex i = 0, size = CFArrayGetCount(cert_array); i < size; ++i) {
      SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(
          const_cast<void*>(CFArrayGetValueAtIndex(cert_array, i)));
      known_roots_.insert(X509Certificate::CalculateFingerprint256(cert));
    }
  }

  ~OSXKnownRootHelper() {}

  std::set<SHA256HashValue, SHA256HashValueLessThan> known_roots_;
};

base::LazyInstance<OSXKnownRootHelper>::Leaky g_known_roots =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

CertVerifyProcMac::CertVerifyProcMac() {}

CertVerifyProcMac::~CertVerifyProcMac() {}

bool CertVerifyProcMac::SupportsAdditionalTrustAnchors() const {
  return false;
}

bool CertVerifyProcMac::SupportsOCSPStapling() const {
  // TODO(rsleevi): Plumb an OCSP response into the Mac system library.
  // https://crbug.com/430714
  return false;
}

int CertVerifyProcMac::VerifyInternal(
    X509Certificate* cert,
    const std::string& hostname,
    const std::string& ocsp_response,
    int flags,
    CRLSet* crl_set,
    const CertificateList& additional_trust_anchors,
    CertVerifyResult* verify_result) {
  ScopedCFTypeRef<CFArrayRef> trust_policies;
  OSStatus status = CreateTrustPolicies(hostname, flags, &trust_policies);
  if (status)
    return NetErrorFromOSStatus(status);

  // Create and configure a SecTrustRef, which takes our certificate(s)
  // and our SSL SecPolicyRef. SecTrustCreateWithCertificates() takes an
  // array of certificates, the first of which is the certificate we're
  // verifying, and the subsequent (optional) certificates are used for
  // chain building.
  ScopedCFTypeRef<CFMutableArrayRef> cert_array(
      cert->CreateOSCertChainForCert());

  // Serialize all calls that may use the Keychain, to work around various
  // issues in OS X 10.6+ with multi-threaded access to Security.framework.
  base::AutoLock lock(crypto::GetMacSecurityServicesLock());

  ScopedCFTypeRef<SecTrustRef> trust_ref;
  SecTrustResultType trust_result = kSecTrustResultDeny;
  ScopedCFTypeRef<CFArrayRef> completed_chain;
  CSSM_TP_APPLE_EVIDENCE_INFO* chain_info = NULL;
  bool candidate_untrusted = true;
  bool candidate_weak = false;

  // OS X lacks proper path discovery; it will take the input certs and never
  // backtrack the graph attempting to discover valid paths.
  // This can create issues in some situations:
  // - When OS X changes the trust store, there may be a chain
  //     A -> B -> C -> D
  //   where OS X trusts D (on some versions) and trusts C (on some versions).
  //   If a server supplies a chain A, B, C (cross-signed by D), then this chain
  //   will successfully validate on systems that trust D, but fail for systems
  //   that trust C. If the server supplies a chain of A -> B, then it forces
  //   all clients to fetch C (via AIA) if they trust D, and not all clients
  //   (notably, Firefox and Android) will do this, thus breaking them.
  //   An example of this is the Verizon Business Services root - GTE CyberTrust
  //   and Baltimore CyberTrust roots represent old and new roots that cause
  //   issues depending on which version of OS X being used.
  //
  // - A server may be (misconfigured) to send an expired intermediate
  //   certificate. On platforms with path discovery, the graph traversal
  //   will back up to immediately before this intermediate, and then
  //   attempt an AIA fetch or retrieval from local store. However, OS X
  //   does not do this, and thus prevents access. While this is ostensibly
  //   a server misconfiguration issue, the fact that it works on other
  //   platforms is a jarring inconsistency for users.
  //
  // - When OS X trusts both C and D (simultaneously), it's possible that the
  //   version of C signed by D is signed using a weak algorithm (e.g. SHA-1),
  //   while the version of C in the trust store's signature doesn't matter.
  //   Since a 'strong' chain exists, it would be desirable to prefer this
  //   chain.
  //
  // - A variant of the above example, it may be that the version of B sent by
  //   the server is signed using a weak algorithm, but the version of B
  //   present in the AIA of A is signed using a strong algorithm. Since a
  //   'strong' chain exists, it would be desirable to prefer this chain.
  //
  // Because of this, the code below first attempts to validate the peer's
  // identity using the supplied chain. If it is not trusted (e.g. the OS only
  // trusts C, but the version of C signed by D was sent, and D is not trusted),
  // or if it contains a weak chain, it will begin lopping off certificates
  // from the end of the chain and attempting to verify. If a stronger, trusted
  // chain is found, it is used, otherwise, the algorithm continues until only
  // the peer's certificate remains.
  //
  // This does cause a performance hit for these users, but only in cases where
  // OS X is building weaker chains than desired, or when it would otherwise
  // fail the connection.
  while (CFArrayGetCount(cert_array) > 0) {
    ScopedCFTypeRef<SecTrustRef> temp_ref;
    SecTrustResultType temp_trust_result = kSecTrustResultDeny;
    ScopedCFTypeRef<CFArrayRef> temp_chain;
    CSSM_TP_APPLE_EVIDENCE_INFO* temp_chain_info = NULL;

    int rv = BuildAndEvaluateSecTrustRef(cert_array, trust_policies, flags,
                                         &temp_ref, &temp_trust_result,
                                         &temp_chain, &temp_chain_info);
    if (rv != OK)
      return rv;

    bool untrusted = (temp_trust_result != kSecTrustResultUnspecified &&
                      temp_trust_result != kSecTrustResultProceed);
    bool weak_chain = false;
    if (CFArrayGetCount(temp_chain) == 0) {
      // If the chain is empty, it cannot be trusted or have recoverable
      // errors.
      DCHECK(untrusted);
      DCHECK_NE(kSecTrustResultRecoverableTrustFailure, temp_trust_result);
    } else {
      CertVerifyResult temp_verify_result;
      bool leaf_is_weak = false;
      GetCertChainInfo(temp_chain, temp_chain_info, &temp_verify_result,
                       &leaf_is_weak);
      weak_chain = !leaf_is_weak &&
                   (temp_verify_result.has_md2 || temp_verify_result.has_md4 ||
                    temp_verify_result.has_md5 || temp_verify_result.has_sha1);
    }
    // Set the result to the current chain if:
    // - This is the first verification attempt. This ensures that if
    //   everything is awful (e.g. it may just be an untrusted cert), that
    //   what is reported is exactly what was sent by the server
    // - If the current chain is trusted, and the old chain was not trusted,
    //   then prefer this chain. This ensures that if there is at least a
    //   valid path to a trust anchor, it's preferred over reporting an error.
    // - If the current chain is trusted, and the old chain is trusted, but
    //   the old chain contained weak algorithms while the current chain only
    //   contains strong algorithms, then prefer the current chain over the
    //   old chain.
    //
    // Note: If the leaf certificate itself is weak, then the only
    // consideration is whether or not there is a trusted chain. That's
    // because no amount of path discovery will fix a weak leaf.
    if (!trust_ref || (!untrusted && (candidate_untrusted ||
                                      (candidate_weak && !weak_chain)))) {
      trust_ref = temp_ref;
      trust_result = temp_trust_result;
      completed_chain = temp_chain;
      chain_info = temp_chain_info;

      candidate_untrusted = untrusted;
      candidate_weak = weak_chain;
    }
    // Short-circuit when a current, trusted chain is found.
    if (!untrusted && !weak_chain)
      break;
    CFArrayRemoveValueAtIndex(cert_array, CFArrayGetCount(cert_array) - 1);
  }

  if (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED)
    verify_result->cert_status |= CERT_STATUS_REV_CHECKING_ENABLED;

  if (crl_set && !CheckRevocationWithCRLSet(completed_chain, crl_set))
    verify_result->cert_status |= CERT_STATUS_REVOKED;

  if (CFArrayGetCount(completed_chain) > 0) {
    bool leaf_is_weak_unused = false;
    GetCertChainInfo(completed_chain, chain_info, verify_result,
                     &leaf_is_weak_unused);
  }

  // As of Security Update 2012-002/OS X 10.7.4, when an RSA key < 1024 bits
  // is encountered, CSSM returns CSSMERR_TP_VERIFY_ACTION_FAILED and adds
  // CSSMERR_CSP_UNSUPPORTED_KEY_SIZE as a certificate status. Avoid mapping
  // the CSSMERR_TP_VERIFY_ACTION_FAILED to CERT_STATUS_INVALID if the only
  // error was due to an unsupported key size.
  bool policy_failed = false;
  bool weak_key_or_signature_algorithm = false;

  // Evaluate the results
  OSStatus cssm_result;
  switch (trust_result) {
    case kSecTrustResultUnspecified:
    case kSecTrustResultProceed:
      // Certificate chain is valid and trusted ("unspecified" indicates that
      // the user has not explicitly set a trust setting)
      break;

    // According to SecTrust.h, kSecTrustResultConfirm isn't returned on 10.5+,
    // and it is marked deprecated in the 10.9 SDK.
    case kSecTrustResultDeny:
      // Certificate chain is explicitly untrusted.
      verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
      break;

    case kSecTrustResultRecoverableTrustFailure:
      // Certificate chain has a failure that can be overridden by the user.
      status = SecTrustGetCssmResultCode(trust_ref, &cssm_result);
      if (status)
        return NetErrorFromOSStatus(status);
      if (cssm_result == CSSMERR_TP_VERIFY_ACTION_FAILED) {
        policy_failed = true;
      } else {
        verify_result->cert_status |= CertStatusFromOSStatus(cssm_result);
      }
      // Walk the chain of error codes in the CSSM_TP_APPLE_EVIDENCE_INFO
      // structure which can catch multiple errors from each certificate.
      for (CFIndex index = 0, chain_count = CFArrayGetCount(completed_chain);
           index < chain_count; ++index) {
        if (chain_info[index].StatusBits & CSSM_CERT_STATUS_EXPIRED ||
            chain_info[index].StatusBits & CSSM_CERT_STATUS_NOT_VALID_YET)
          verify_result->cert_status |= CERT_STATUS_DATE_INVALID;
        if (!IsCertStatusError(verify_result->cert_status) &&
            chain_info[index].NumStatusCodes == 0) {
          LOG(WARNING) << "chain_info[" << index << "].NumStatusCodes is 0"
                          ", chain_info[" << index << "].StatusBits is "
                       << chain_info[index].StatusBits;
        }
        for (uint32_t status_code_index = 0;
             status_code_index < chain_info[index].NumStatusCodes;
             ++status_code_index) {
          // As of OS X 10.9, attempting to verify a certificate chain that
          // contains a weak signature algorithm (MD2, MD5) in an intermediate
          // or leaf cert will be treated as a (recoverable) policy validation
          // failure, with the status code CSSMERR_TP_INVALID_CERTIFICATE
          // added to the Status Codes. Don't treat this code as an invalid
          // certificate; instead, map it to a weak key. Any truly invalid
          // certificates will have the major error (cssm_result) set to
          // CSSMERR_TP_INVALID_CERTIFICATE, rather than
          // CSSMERR_TP_VERIFY_ACTION_FAILED.
          CertStatus mapped_status = 0;
          if (policy_failed &&
              chain_info[index].StatusCodes[status_code_index] ==
                  CSSMERR_TP_INVALID_CERTIFICATE) {
              mapped_status = CERT_STATUS_WEAK_SIGNATURE_ALGORITHM;
              weak_key_or_signature_algorithm = true;
          } else {
              mapped_status = CertStatusFromOSStatus(
                  chain_info[index].StatusCodes[status_code_index]);
              if (mapped_status == CERT_STATUS_WEAK_KEY)
                weak_key_or_signature_algorithm = true;
          }
          verify_result->cert_status |= mapped_status;
        }
      }
      if (policy_failed && !weak_key_or_signature_algorithm) {
        // If CSSMERR_TP_VERIFY_ACTION_FAILED wasn't returned due to a weak
        // key, map it back to an appropriate error code.
        verify_result->cert_status |= CertStatusFromOSStatus(cssm_result);
      }
      if (!IsCertStatusError(verify_result->cert_status)) {
        LOG(ERROR) << "cssm_result=" << cssm_result;
        verify_result->cert_status |= CERT_STATUS_INVALID;
        NOTREACHED();
      }
      break;

    default:
      status = SecTrustGetCssmResultCode(trust_ref, &cssm_result);
      if (status)
        return NetErrorFromOSStatus(status);
      verify_result->cert_status |= CertStatusFromOSStatus(cssm_result);
      if (!IsCertStatusError(verify_result->cert_status)) {
        LOG(WARNING) << "trust_result=" << trust_result;
        verify_result->cert_status |= CERT_STATUS_INVALID;
      }
      break;
  }

  // Perform hostname verification independent of SecTrustEvaluate. In order to
  // do so, mask off any reported name errors first.
  verify_result->cert_status &= ~CERT_STATUS_COMMON_NAME_INVALID;
  if (!cert->VerifyNameMatch(hostname,
                             &verify_result->common_name_fallback_used)) {
    verify_result->cert_status |= CERT_STATUS_COMMON_NAME_INVALID;
  }

  // TODO(wtc): Suppress CERT_STATUS_NO_REVOCATION_MECHANISM for now to be
  // compatible with Windows, which in turn implements this behavior to be
  // compatible with WinHTTP, which doesn't report this error (bug 3004).
  verify_result->cert_status &= ~CERT_STATUS_NO_REVOCATION_MECHANISM;

  AppendPublicKeyHashes(completed_chain, &verify_result->public_key_hashes);
  verify_result->is_issued_by_known_root =
      g_known_roots.Get().IsIssuedByKnownRoot(completed_chain);

  if (IsCertStatusError(verify_result->cert_status))
    return MapCertStatusToNetError(verify_result->cert_status);

  if (flags & CertVerifier::VERIFY_EV_CERT) {
    // Determine the certificate's EV status using SecTrustCopyExtendedResult(),
    // which is an internal/private API function added in OS X 10.5.7.
    // Note: "ExtendedResult" means extended validation results.
    CFBundleRef bundle =
        CFBundleGetBundleWithIdentifier(CFSTR("com.apple.security"));
    if (bundle) {
      SecTrustCopyExtendedResultFuncPtr copy_extended_result =
          reinterpret_cast<SecTrustCopyExtendedResultFuncPtr>(
              CFBundleGetFunctionPointerForName(bundle,
                  CFSTR("SecTrustCopyExtendedResult")));
      if (copy_extended_result) {
        CFDictionaryRef ev_dict_temp = NULL;
        status = copy_extended_result(trust_ref, &ev_dict_temp);
        ScopedCFTypeRef<CFDictionaryRef> ev_dict(ev_dict_temp);
        ev_dict_temp = NULL;
        if (status == noErr && ev_dict) {
          // In 10.7.3, SecTrustCopyExtendedResult returns noErr and populates
          // ev_dict even for non-EV certificates, but only EV certificates
          // will cause ev_dict to contain kSecEVOrganizationName. In previous
          // releases, SecTrustCopyExtendedResult would only return noErr and
          // populate ev_dict for EV certificates, but would always include
          // kSecEVOrganizationName in that case, so checking for this key is
          // appropriate for all known versions of SecTrustCopyExtendedResult.
          // The actual organization name is unneeded here and can be accessed
          // through other means. All that matters here is the OS' conception
          // of whether or not the certificate is EV.
          if (CFDictionaryContainsKey(ev_dict,
                                      kSecEVOrganizationName)) {
            verify_result->cert_status |= CERT_STATUS_IS_EV;
            if (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED_EV_ONLY)
              verify_result->cert_status |= CERT_STATUS_REV_CHECKING_ENABLED;
          }
        }
      }
    }
  }

  return OK;
}

}  // namespace net

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"
