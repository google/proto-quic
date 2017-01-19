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
#include "base/mac/mac_util.h"
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
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/internal/certificate_policies.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/test_keychain_search_list_mac.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_mac.h"

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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
// validate a certificate for an SSL server. |flags| is a bitwise-OR of
// VerifyFlags that can further alter how trust is validated, such as how
// revocation is checked. If successful, returns noErr, and stores the
// resultant array of SecPolicyRefs in |policies|.
OSStatus CreateTrustPolicies(int flags, ScopedCFTypeRef<CFArrayRef>* policies) {
  ScopedCFTypeRef<CFMutableArrayRef> local_policies(
      CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
  if (!local_policies)
    return memFullErr;

  SecPolicyRef ssl_policy;
  OSStatus status =
      x509_util::CreateSSLServerPolicy(std::string(), &ssl_policy);
  if (status)
    return status;
  CFArrayAppendValue(local_policies, ssl_policy);
  CFRelease(ssl_policy);

  // Explicitly add revocation policies, in order to override system
  // revocation checking policies and instead respect the application-level
  // revocation preference.
  status = x509_util::CreateRevocationPolicies(
      (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED), local_policies);
  if (status)
    return status;

  policies->reset(local_policies.release());
  return noErr;
}

// Stores the constructed certificate chain |cert_chain| into
// |*verify_result|. |cert_chain| must not be empty.
void CopyCertChainToVerifyResult(CFArrayRef cert_chain,
                                 CertVerifyResult* verify_result) {
  DCHECK_LT(0, CFArrayGetCount(cert_chain));

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
  }
  if (!verified_cert) {
    NOTREACHED();
    return;
  }

  verify_result->verified_cert =
      X509Certificate::CreateFromHandle(verified_cert, verified_chain);
}

// Returns true if the intermediates (excluding trusted certificates) use a
// weak hashing algorithm, but the target does not use a weak hash.
bool IsWeakChainBasedOnHashingAlgorithms(
    CFArrayRef cert_chain,
    CSSM_TP_APPLE_EVIDENCE_INFO* chain_info) {
  DCHECK_LT(0, CFArrayGetCount(cert_chain));

  bool intermediates_contain_weak_hash = false;
  bool leaf_uses_weak_hash = false;

  for (CFIndex i = 0, count = CFArrayGetCount(cert_chain); i < count; ++i) {
    SecCertificateRef chain_cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(cert_chain, i)));

    if ((chain_info[i].StatusBits & CSSM_CERT_STATUS_IS_IN_ANCHORS) ||
        (chain_info[i].StatusBits & CSSM_CERT_STATUS_IS_ROOT)) {
      // The current certificate is either in the user's trusted store or is
      // a root (self-signed) certificate. Ignore the signature algorithm for
      // these certificates, as it is meaningless for security. We allow
      // self-signed certificates (i == 0 & IS_ROOT), since we accept that
      // any security assertions by such a cert are inherently meaningless.
      continue;
    }

    X509Certificate::SignatureHashAlgorithm hash_algorithm =
        X509Certificate::GetSignatureHashAlgorithm(chain_cert);

    switch (hash_algorithm) {
      case X509Certificate::kSignatureHashAlgorithmMd2:
      case X509Certificate::kSignatureHashAlgorithmMd4:
      case X509Certificate::kSignatureHashAlgorithmMd5:
      case X509Certificate::kSignatureHashAlgorithmSha1:
        if (i == 0) {
          leaf_uses_weak_hash = true;
        } else {
          intermediates_contain_weak_hash = true;
        }
        break;
      case X509Certificate::kSignatureHashAlgorithmOther:
        break;
    }
  }

  return !leaf_uses_weak_hash && intermediates_contain_weak_hash;
}

using ExtensionsMap = std::map<net::der::Input, net::ParsedExtension>;

// Helper that looks up an extension by OID given a map of extensions.
bool GetExtensionValue(const ExtensionsMap& extensions,
                       const net::der::Input& oid,
                       net::der::Input* value) {
  auto it = extensions.find(oid);
  if (it == extensions.end())
    return false;
  *value = it->second.value;
  return true;
}

// Checks if |*cert| has a Certificate Policies extension containing either
// of |ev_policy_oid| or anyPolicy.
bool HasPolicyOrAnyPolicy(const ParsedCertificate* cert,
                          const der::Input& ev_policy_oid) {
  der::Input extension_value;
  if (!GetExtensionValue(cert->unparsed_extensions(), CertificatePoliciesOid(),
                         &extension_value)) {
    return false;
  }

  std::vector<der::Input> policies;
  if (!ParseCertificatePoliciesExtension(extension_value, &policies))
    return false;

  for (const der::Input& policy_oid : policies) {
    if (policy_oid == ev_policy_oid || policy_oid == AnyPolicy())
      return true;
  }
  return false;
}

// Looks for known EV policy OIDs in |cert_input|, if one is found it will be
// stored in |*ev_policy_oid| as a DER-encoded OID value (no tag or length).
void GetCandidateEVPolicy(const X509Certificate* cert_input,
                          std::string* ev_policy_oid) {
  ev_policy_oid->clear();

  std::string der_cert;
  if (!X509Certificate::GetDEREncoded(cert_input->os_cert_handle(),
                                      &der_cert)) {
    return;
  }

  scoped_refptr<ParsedCertificate> cert(
      ParsedCertificate::Create(der_cert, {}, nullptr));
  if (!cert)
    return;

  der::Input extension_value;
  if (!GetExtensionValue(cert->unparsed_extensions(), CertificatePoliciesOid(),
                         &extension_value)) {
    return;
  }

  std::vector<der::Input> policies;
  if (!ParseCertificatePoliciesExtension(extension_value, &policies))
    return;

  EVRootCAMetadata* metadata = EVRootCAMetadata::GetInstance();
  for (const der::Input& policy_oid : policies) {
    if (metadata->IsEVPolicyOID(policy_oid)) {
      *ev_policy_oid = policy_oid.AsString();
      return;
    }
  }
}

// Checks that the certificate chain of |cert| has policies consistent with
// |ev_policy_oid_string|. The leaf is not checked, as it is assumed that is
// where the policy came from.
bool CheckCertChainEV(const X509Certificate* cert,
                      const std::string& ev_policy_oid_string) {
  der::Input ev_policy_oid(&ev_policy_oid_string);
  X509Certificate::OSCertHandles os_cert_chain =
      cert->GetIntermediateCertificates();

  // Root should have matching policy in EVRootCAMetadata.
  std::string der_cert;
  if (!X509Certificate::GetDEREncoded(os_cert_chain.back(), &der_cert))
    return false;
  SHA1HashValue weak_fingerprint;
  base::SHA1HashBytes(reinterpret_cast<const unsigned char*>(der_cert.data()),
                      der_cert.size(), weak_fingerprint.data);
  EVRootCAMetadata* metadata = EVRootCAMetadata::GetInstance();
  if (!metadata->HasEVPolicyOID(weak_fingerprint, ev_policy_oid))
    return false;

  // Intermediates should have Certificate Policies extension with the EV policy
  // or AnyPolicy.
  for (size_t i = 0; i < os_cert_chain.size() - 1; ++i) {
    std::string der_cert;
    if (!X509Certificate::GetDEREncoded(os_cert_chain[i], &der_cert))
      return false;
    scoped_refptr<ParsedCertificate> intermediate_cert(
        ParsedCertificate::Create(der_cert, {}, nullptr));
    if (!intermediate_cert)
      return false;
    if (!HasPolicyOrAnyPolicy(intermediate_cert.get(), ev_policy_oid))
      return false;
  }

  return true;
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

enum CRLSetResult {
  kCRLSetOk,
  kCRLSetRevoked,
  kCRLSetUnknown,
};

// CheckRevocationWithCRLSet attempts to check each element of |cert_list|
// against |crl_set|. It returns:
//   kCRLSetRevoked: if any element of the chain is known to have been revoked.
//   kCRLSetUnknown: if there is no fresh information about the leaf
//       certificate in the chain or if the CRLSet has expired.
//
//       Only the leaf certificate is considered for coverage because some
//       intermediates have CRLs with no revocations (after filtering) and
//       those CRLs are pruned from the CRLSet at generation time. This means
//       that some EV sites would otherwise take the hit of an OCSP lookup for
//       no reason.
//   kCRLSetOk: otherwise.
CRLSetResult CheckRevocationWithCRLSet(CFArrayRef chain, CRLSet* crl_set) {
  if (CFArrayGetCount(chain) == 0)
    return kCRLSetOk;

  // error is set to true if any errors are found. It causes such chains to be
  // considered as not covered.
  bool error = false;
  // last_covered is set to the coverage state of the previous certificate. The
  // certificates are iterated over backwards thus, after the iteration,
  // |last_covered| contains the coverage state of the leaf certificate.
  bool last_covered = false;

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
      error = true;
      continue;
    }
    base::StringPiece der_bytes(reinterpret_cast<const char*>(cert_data.Data),
                                cert_data.Length);
    base::StringPiece spki;
    if (!asn1::ExtractSPKIFromDERCert(der_bytes, &spki)) {
      NOTREACHED();
      error = true;
      continue;
    }

    const std::string spki_hash = crypto::SHA256HashString(spki);
    x509_util::CSSMCachedCertificate cached_cert;
    if (cached_cert.Init(cert) != CSSM_OK) {
      NOTREACHED();
      error = true;
      continue;
    }
    x509_util::CSSMFieldValue serial_number;
    err = cached_cert.GetField(&CSSMOID_X509V1SerialNumber, &serial_number);
    if (err || !serial_number.field()) {
      NOTREACHED();
      error = true;
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
        return kCRLSetRevoked;
      case CRLSet::UNKNOWN:
        last_covered = false;
        continue;
      case CRLSet::GOOD:
        last_covered = true;
        continue;
      default:
        NOTREACHED();
        error = true;
        continue;
    }
  }

  if (error || !last_covered || crl_set->IsExpired())
    return kCRLSetUnknown;
  return kCRLSetOk;
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
                                CFArrayRef keychain_search_list,
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

  if (keychain_search_list) {
    status = SecTrustSetKeychains(tmp_trust, keychain_search_list);
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

// Runs path building & verification loop for |cert|, given |flags|. This is
// split into a separate function so verification can be repeated with different
// flags. This function does not handle EV.
int VerifyWithGivenFlags(X509Certificate* cert,
                         const std::string& hostname,
                         const int flags,
                         CRLSet* crl_set,
                         CertVerifyResult* verify_result,
                         CRLSetResult* completed_chain_crl_result) {
  ScopedCFTypeRef<CFArrayRef> trust_policies;
  OSStatus status = CreateTrustPolicies(flags, &trust_policies);
  if (status)
    return NetErrorFromOSStatus(status);

  *completed_chain_crl_result = kCRLSetUnknown;

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
  // - A user keychain may contain a less desirable intermediate or root.
  //   OS X gives the user keychains higher priority than the system keychain,
  //   so it may build a weak chain.
  //
  // Because of this, the code below first attempts to validate the peer's
  // identity using the supplied chain. If it is not trusted (e.g. the OS only
  // trusts C, but the version of C signed by D was sent, and D is not trusted),
  // or if it contains a weak chain, it will begin lopping off certificates
  // from the end of the chain and attempting to verify. If a stronger, trusted
  // chain is found, it is used, otherwise, the algorithm continues until only
  // the peer's certificate remains.
  //
  // If the loop does not find a trusted chain, the loop will be repeated with
  // the keychain search order altered to give priority to the System Roots
  // keychain.
  //
  // This does cause a performance hit for these users, but only in cases where
  // OS X is building weaker chains than desired, or when it would otherwise
  // fail the connection.
  for (bool try_reordered_keychain : {false, true}) {
    ScopedCFTypeRef<CFArrayRef> scoped_alternate_keychain_search_list;
    if (TestKeychainSearchList::HasInstance()) {
      // Unit tests need to be able to hermetically simulate situations where a
      // user has an undesirable certificate in a per-user keychain.
      // Adding/Removing a Keychain using SecKeychainCreate/SecKeychainDelete
      // has global side effects, which would break other tests and processes
      // running on the same machine, so instead tests may load pre-created
      // keychains using SecKeychainOpen and then inject them through
      // TestKeychainSearchList.
      CFArrayRef keychain_search_list;
      status = TestKeychainSearchList::GetInstance()->CopySearchList(
          &keychain_search_list);
      if (status)
        return NetErrorFromOSStatus(status);
      scoped_alternate_keychain_search_list.reset(keychain_search_list);
    }
    if (try_reordered_keychain) {
      // If a TestKeychainSearchList is present, it will have already set
      // |scoped_alternate_keychain_search_list|, which will be used as the
      // basis for reordering the keychain. Otherwise, get the current keychain
      // search list and use that.
      if (!scoped_alternate_keychain_search_list) {
        CFArrayRef keychain_search_list;
        status = SecKeychainCopySearchList(&keychain_search_list);
        if (status)
          return NetErrorFromOSStatus(status);
        scoped_alternate_keychain_search_list.reset(keychain_search_list);
      }
      CFMutableArrayRef mutable_keychain_search_list = CFArrayCreateMutableCopy(
          kCFAllocatorDefault,
          CFArrayGetCount(scoped_alternate_keychain_search_list.get()) + 1,
          scoped_alternate_keychain_search_list.get());
      if (!mutable_keychain_search_list)
        return ERR_OUT_OF_MEMORY;
      scoped_alternate_keychain_search_list.reset(mutable_keychain_search_list);

      SecKeychainRef keychain;
      // Get a reference to the System Roots keychain. The System Roots
      // keychain is not normally present in the keychain search list, but is
      // implicitly checked after the keychains in the search list. By
      // including it directly, force it to be checked first.  This is a gross
      // hack, but the path is known to be valid on OS X 10.9-10.11.
      status = SecKeychainOpen(
          "/System/Library/Keychains/SystemRootCertificates.keychain",
          &keychain);
      if (status)
        return NetErrorFromOSStatus(status);
      ScopedCFTypeRef<SecKeychainRef> scoped_keychain(keychain);

      CFArrayInsertValueAtIndex(mutable_keychain_search_list, 0, keychain);
    }

    ScopedCFTypeRef<CFMutableArrayRef> cert_array(
        cert->CreateOSCertChainForCert());

    // Beginning with the certificate chain as supplied by the server, attempt
    // to verify the chain. If a failure is encountered, trim a certificate
    // from the end (so long as one remains) and retry, in the hope of forcing
    // OS X to find a better path.
    while (CFArrayGetCount(cert_array) > 0) {
      ScopedCFTypeRef<SecTrustRef> temp_ref;
      SecTrustResultType temp_trust_result = kSecTrustResultDeny;
      ScopedCFTypeRef<CFArrayRef> temp_chain;
      CSSM_TP_APPLE_EVIDENCE_INFO* temp_chain_info = NULL;

      int rv = BuildAndEvaluateSecTrustRef(
          cert_array, trust_policies, flags,
          scoped_alternate_keychain_search_list.get(), &temp_ref,
          &temp_trust_result, &temp_chain, &temp_chain_info);
      if (rv != OK)
        return rv;

      // Check to see if the path |temp_chain| has been revoked. This is less
      // than ideal to perform after path building, rather than during, because
      // there may be multiple paths to trust anchors, and only some of them
      // are revoked. Ideally, CRLSets would be part of path building, which
      // they are when using NSS (Linux) or CryptoAPI (Windows).
      //
      // The CRLSet checking is performed inside the loop in the hope that if a
      // path is revoked, it's an older path, and the only reason it was built
      // is because the server forced it (by supplying an older or less
      // desirable intermediate) or because the user had installed a
      // certificate in their Keychain forcing this path. However, this means
      // its still possible for a CRLSet block of an intermediate to prevent
      // access, even when there is a 'good' chain. To fully remedy this, a
      // solution might be to have CRLSets contain enough knowledge about what
      // the 'desired' path might be, but for the time being, the
      // implementation is kept as 'simple' as it can be.
      CRLSetResult crl_result = kCRLSetUnknown;
      if (crl_set)
        crl_result = CheckRevocationWithCRLSet(temp_chain, crl_set);
      bool untrusted = (temp_trust_result != kSecTrustResultUnspecified &&
                        temp_trust_result != kSecTrustResultProceed) ||
                       crl_result == kCRLSetRevoked;
      bool weak_chain = false;
      if (CFArrayGetCount(temp_chain) == 0) {
        // If the chain is empty, it cannot be trusted or have recoverable
        // errors.
        DCHECK(untrusted);
        DCHECK_NE(kSecTrustResultRecoverableTrustFailure, temp_trust_result);
      } else {
        weak_chain =
            IsWeakChainBasedOnHashingAlgorithms(temp_chain, temp_chain_info);
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
        *completed_chain_crl_result = crl_result;
        chain_info = temp_chain_info;

        candidate_untrusted = untrusted;
        candidate_weak = weak_chain;
      }
      // Short-circuit when a current, trusted chain is found.
      if (!untrusted && !weak_chain)
        break;
      CFArrayRemoveValueAtIndex(cert_array, CFArrayGetCount(cert_array) - 1);
    }
    // Short-circuit when a current, trusted chain is found.
    if (!candidate_untrusted && !candidate_weak)
      break;
  }

  if (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED)
    verify_result->cert_status |= CERT_STATUS_REV_CHECKING_ENABLED;

  if (*completed_chain_crl_result == kCRLSetRevoked)
    verify_result->cert_status |= CERT_STATUS_REVOKED;

  if (CFArrayGetCount(completed_chain) > 0) {
    CopyCertChainToVerifyResult(completed_chain, verify_result);
  }

  // As of Security Update 2012-002/OS X 10.7.4, when an RSA key < 1024 bits
  // is encountered, CSSM returns CSSMERR_TP_VERIFY_ACTION_FAILED and adds
  // CSSMERR_CSP_UNSUPPORTED_KEY_SIZE as a certificate status. Avoid mapping
  // the CSSMERR_TP_VERIFY_ACTION_FAILED to CERT_STATUS_INVALID if the only
  // error was due to an unsupported key size.
  bool policy_failed = false;
  bool policy_fail_already_mapped = false;
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
            policy_fail_already_mapped = true;
          } else if (policy_failed &&
                     (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED) &&
                     chain_info[index].StatusCodes[status_code_index] ==
                         CSSMERR_TP_VERIFY_ACTION_FAILED &&
                     base::mac::IsAtLeastOS10_12()) {
            // On 10.12, using kSecRevocationRequirePositiveResponse flag
            // causes a CSSMERR_TP_VERIFY_ACTION_FAILED status if revocation
            // couldn't be checked. (Note: even if the cert had no
            // crlDistributionPoints or OCSP AIA.)
            mapped_status = CERT_STATUS_UNABLE_TO_CHECK_REVOCATION;
            policy_fail_already_mapped = true;
          } else {
            mapped_status = CertStatusFromOSStatus(
                chain_info[index].StatusCodes[status_code_index]);
            if (mapped_status == CERT_STATUS_WEAK_KEY) {
              weak_key_or_signature_algorithm = true;
              policy_fail_already_mapped = true;
            }
          }
          verify_result->cert_status |= mapped_status;
        }
      }
      if (policy_failed && !policy_fail_already_mapped) {
        // If CSSMERR_TP_VERIFY_ACTION_FAILED wasn't returned due to a weak
        // key or problem checking revocation, map it back to an appropriate
        // error code.
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

  return OK;
}

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
  // Save the input state of |*verify_result|, which may be needed to re-do
  // verification with different flags.
  const CertVerifyResult input_verify_result(*verify_result);

  // If EV verification is enabled, check for EV policy in leaf cert.
  std::string candidate_ev_policy_oid;
  if (flags & CertVerifier::VERIFY_EV_CERT)
    GetCandidateEVPolicy(cert, &candidate_ev_policy_oid);

  CRLSetResult completed_chain_crl_result;
  int rv = VerifyWithGivenFlags(cert, hostname, flags, crl_set, verify_result,
                                &completed_chain_crl_result);
  if (rv != OK)
    return rv;

  if (!candidate_ev_policy_oid.empty() &&
      CheckCertChainEV(verify_result->verified_cert.get(),
                       candidate_ev_policy_oid)) {
    // EV policies check out and the verification succeeded. See if revocation
    // checking still needs to be done before it can be marked as EV.
    if (completed_chain_crl_result == kCRLSetUnknown &&
        (flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED_EV_ONLY) &&
        !(flags & CertVerifier::VERIFY_REV_CHECKING_ENABLED)) {
      // If this is an EV cert and it wasn't covered by CRLSets and revocation
      // checking wasn't already on, try again with revocation forced on.
      //
      // Restore the input state of |*verify_result|, so that the
      // re-verification starts with a clean slate.
      *verify_result = input_verify_result;
      int tmp_rv = VerifyWithGivenFlags(
          verify_result->verified_cert.get(), hostname,
          flags | CertVerifier::VERIFY_REV_CHECKING_ENABLED, crl_set,
          verify_result, &completed_chain_crl_result);
      // If re-verification failed, return those results without setting EV
      // status.
      if (tmp_rv != OK)
        return tmp_rv;
      // Otherwise, fall through and add the EV status flag.
    }
    // EV cert and it was covered by CRLSets or revocation checking passed.
    verify_result->cert_status |= CERT_STATUS_IS_EV;
  }

  return OK;
}

}  // namespace net

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"
