// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc.h"

#include <stdint.h>

#include <algorithm>

#include "base/metrics/histogram.h"
#include "base/metrics/histogram_macros.h"
#include "base/sha1.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/url_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc_whitelist.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/x509_certificate.h"
#include "url/url_canon.h"

#if defined(USE_NSS_CERTS)
#include "net/cert/cert_verify_proc_nss.h"
#elif defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
#include "net/cert/cert_verify_proc_openssl.h"
#elif defined(OS_ANDROID)
#include "net/cert/cert_verify_proc_android.h"
#elif defined(OS_IOS)
#include "net/cert/cert_verify_proc_ios.h"
#elif defined(OS_MACOSX)
#include "net/cert/cert_verify_proc_mac.h"
#elif defined(OS_WIN)
#include "net/cert/cert_verify_proc_win.h"
#else
#error Implement certificate verification.
#endif

namespace net {

namespace {

// Constants used to build histogram names
const char kLeafCert[] = "Leaf";
const char kIntermediateCert[] = "Intermediate";
const char kRootCert[] = "Root";
// Matches the order of X509Certificate::PublicKeyType
const char* const kCertTypeStrings[] = {
    "Unknown",
    "RSA",
    "DSA",
    "ECDSA",
    "DH",
    "ECDH"
};
// Histogram buckets for RSA/DSA/DH key sizes.
const int kRsaDsaKeySizes[] = {512, 768, 1024, 1536, 2048, 3072, 4096, 8192,
                               16384};
// Histogram buckets for ECDSA/ECDH key sizes. The list is based upon the FIPS
// 186-4 approved curves.
const int kEccKeySizes[] = {163, 192, 224, 233, 256, 283, 384, 409, 521, 571};

const char* CertTypeToString(int cert_type) {
  if (cert_type < 0 ||
      static_cast<size_t>(cert_type) >= arraysize(kCertTypeStrings)) {
    return "Unsupported";
  }
  return kCertTypeStrings[cert_type];
}

void RecordPublicKeyHistogram(const char* chain_position,
                              bool baseline_keysize_applies,
                              size_t size_bits,
                              X509Certificate::PublicKeyType cert_type) {
  std::string histogram_name =
      base::StringPrintf("CertificateType2.%s.%s.%s",
                         baseline_keysize_applies ? "BR" : "NonBR",
                         chain_position,
                         CertTypeToString(cert_type));
  // Do not use UMA_HISTOGRAM_... macros here, as it caches the Histogram
  // instance and thus only works if |histogram_name| is constant.
  base::HistogramBase* counter = NULL;

  // Histogram buckets are contingent upon the underlying algorithm being used.
  if (cert_type == X509Certificate::kPublicKeyTypeECDH ||
      cert_type == X509Certificate::kPublicKeyTypeECDSA) {
    // Typical key sizes match SECP/FIPS 186-3 recommendations for prime and
    // binary curves - which range from 163 bits to 571 bits.
    counter = base::CustomHistogram::FactoryGet(
        histogram_name,
        base::CustomHistogram::ArrayToCustomRanges(kEccKeySizes,
                                                   arraysize(kEccKeySizes)),
        base::HistogramBase::kUmaTargetedHistogramFlag);
  } else {
    // Key sizes < 1024 bits should cause errors, while key sizes > 16K are not
    // uniformly supported by the underlying cryptographic libraries.
    counter = base::CustomHistogram::FactoryGet(
        histogram_name,
        base::CustomHistogram::ArrayToCustomRanges(kRsaDsaKeySizes,
                                                   arraysize(kRsaDsaKeySizes)),
        base::HistogramBase::kUmaTargetedHistogramFlag);
  }
  counter->Add(size_bits);
}

// Returns true if |type| is |kPublicKeyTypeRSA| or |kPublicKeyTypeDSA|, and
// if |size_bits| is < 1024. Note that this means there may be false
// negatives: keys for other algorithms and which are weak will pass this
// test.
bool IsWeakKey(X509Certificate::PublicKeyType type, size_t size_bits) {
  switch (type) {
    case X509Certificate::kPublicKeyTypeRSA:
    case X509Certificate::kPublicKeyTypeDSA:
      return size_bits < 1024;
    default:
      return false;
  }
}

// Returns true if |cert| contains a known-weak key. Additionally, histograms
// the observed keys for future tightening of the definition of what
// constitutes a weak key.
bool ExaminePublicKeys(const scoped_refptr<X509Certificate>& cert,
                       bool should_histogram) {
  // The effective date of the CA/Browser Forum's Baseline Requirements -
  // 2012-07-01 00:00:00 UTC.
  const base::Time kBaselineEffectiveDate =
      base::Time::FromInternalValue(INT64_C(12985574400000000));
  // The effective date of the key size requirements from Appendix A, v1.1.5
  // 2014-01-01 00:00:00 UTC.
  const base::Time kBaselineKeysizeEffectiveDate =
      base::Time::FromInternalValue(INT64_C(13033008000000000));

  size_t size_bits = 0;
  X509Certificate::PublicKeyType type = X509Certificate::kPublicKeyTypeUnknown;
  bool weak_key = false;
  bool baseline_keysize_applies =
      cert->valid_start() >= kBaselineEffectiveDate &&
      cert->valid_expiry() >= kBaselineKeysizeEffectiveDate;

  X509Certificate::GetPublicKeyInfo(cert->os_cert_handle(), &size_bits, &type);
  if (should_histogram) {
    RecordPublicKeyHistogram(kLeafCert, baseline_keysize_applies, size_bits,
                             type);
  }
  if (IsWeakKey(type, size_bits))
    weak_key = true;

  const X509Certificate::OSCertHandles& intermediates =
      cert->GetIntermediateCertificates();
  for (size_t i = 0; i < intermediates.size(); ++i) {
    X509Certificate::GetPublicKeyInfo(intermediates[i], &size_bits, &type);
    if (should_histogram) {
      RecordPublicKeyHistogram(
          (i < intermediates.size() - 1) ? kIntermediateCert : kRootCert,
          baseline_keysize_applies,
          size_bits,
          type);
    }
    if (!weak_key && IsWeakKey(type, size_bits))
      weak_key = true;
  }

  return weak_key;
}

// Beginning with Ballot 118, ratified in the Baseline Requirements v1.2.1,
// CAs MUST NOT issue SHA-1 certificates beginning on 1 January 2016.
bool IsPastSHA1DeprecationDate(const X509Certificate& cert) {
  const base::Time& start = cert.valid_start();
  if (start.is_max() || start.is_null())
    return true;
  // 2016-01-01 00:00:00 UTC.
  const base::Time kSHA1DeprecationDate =
      base::Time::FromInternalValue(INT64_C(13096080000000000));
  return start >= kSHA1DeprecationDate;
}

// Comparison functor used for binary searching whether a given HashValue,
// which MUST be a SHA-256 hash, is contained with an array of SHA-256
// hashes.
struct HashToArrayComparator {
  template <size_t N>
  bool operator()(const uint8_t(&lhs)[N], const HashValue& rhs) const {
    static_assert(N == crypto::kSHA256Length,
                  "Only SHA-256 hashes are supported");
    return memcmp(lhs, rhs.data(), crypto::kSHA256Length) < 0;
  }

  template <size_t N>
  bool operator()(const HashValue& lhs, const uint8_t(&rhs)[N]) const {
    static_assert(N == crypto::kSHA256Length,
                  "Only SHA-256 hashes are supported");
    return memcmp(lhs.data(), rhs, crypto::kSHA256Length) < 0;
  }
};

}  // namespace

// static
CertVerifyProc* CertVerifyProc::CreateDefault() {
#if defined(USE_NSS_CERTS)
  return new CertVerifyProcNSS();
#elif defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
  return new CertVerifyProcOpenSSL();
#elif defined(OS_ANDROID)
  return new CertVerifyProcAndroid();
#elif defined(OS_IOS)
  return new CertVerifyProcIOS();
#elif defined(OS_MACOSX)
  return new CertVerifyProcMac();
#elif defined(OS_WIN)
  return new CertVerifyProcWin();
#else
  return NULL;
#endif
}

CertVerifyProc::CertVerifyProc() {}

CertVerifyProc::~CertVerifyProc() {}

int CertVerifyProc::Verify(X509Certificate* cert,
                           const std::string& hostname,
                           const std::string& ocsp_response,
                           int flags,
                           CRLSet* crl_set,
                           const CertificateList& additional_trust_anchors,
                           CertVerifyResult* verify_result) {
  verify_result->Reset();
  verify_result->verified_cert = cert;

  if (IsBlacklisted(cert)) {
    verify_result->cert_status |= CERT_STATUS_REVOKED;
    return ERR_CERT_REVOKED;
  }

  // We do online revocation checking for EV certificates that aren't covered
  // by a fresh CRLSet.
  // TODO(rsleevi): http://crbug.com/142974 - Allow preferences to fully
  // disable revocation checking.
  if (flags & CertVerifier::VERIFY_EV_CERT)
    flags |= CertVerifier::VERIFY_REV_CHECKING_ENABLED_EV_ONLY;

  int rv = VerifyInternal(cert, hostname, ocsp_response, flags, crl_set,
                          additional_trust_anchors, verify_result);

  UMA_HISTOGRAM_BOOLEAN("Net.CertCommonNameFallback",
                        verify_result->common_name_fallback_used);
  if (!verify_result->is_issued_by_known_root) {
    UMA_HISTOGRAM_BOOLEAN("Net.CertCommonNameFallbackPrivateCA",
                          verify_result->common_name_fallback_used);
  }

  // This check is done after VerifyInternal so that VerifyInternal can fill
  // in the list of public key hashes.
  if (IsPublicKeyBlacklisted(verify_result->public_key_hashes)) {
    verify_result->cert_status |= CERT_STATUS_REVOKED;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  std::vector<std::string> dns_names, ip_addrs;
  cert->GetSubjectAltName(&dns_names, &ip_addrs);
  if (HasNameConstraintsViolation(verify_result->public_key_hashes,
                                  cert->subject().common_name,
                                  dns_names,
                                  ip_addrs)) {
    verify_result->cert_status |= CERT_STATUS_NAME_CONSTRAINT_VIOLATION;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  if (IsNonWhitelistedCertificate(*verify_result->verified_cert,
                                  verify_result->public_key_hashes)) {
    verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Check for weak keys in the entire verified chain.
  bool weak_key = ExaminePublicKeys(verify_result->verified_cert,
                                    verify_result->is_issued_by_known_root);

  if (weak_key) {
    verify_result->cert_status |= CERT_STATUS_WEAK_KEY;
    // Avoid replacing a more serious error, such as an OS/library failure,
    // by ensuring that if verification failed, it failed with a certificate
    // error.
    if (rv == OK || IsCertificateError(rv))
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Treat certificates signed using broken signature algorithms as invalid.
  if (verify_result->has_md2 || verify_result->has_md4) {
    verify_result->cert_status |= CERT_STATUS_INVALID;
    rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  if (verify_result->has_sha1)
    verify_result->cert_status |= CERT_STATUS_SHA1_SIGNATURE_PRESENT;

  // Flag certificates using weak signature algorithms.
  // The CA/Browser Forum Baseline Requirements (beginning with v1.2.1)
  // prohibits SHA-1 certificates from being issued beginning on
  // 1 January 2016. Ideally, all of SHA-1 in new certificates would be
  // disabled on this date, but enterprises need more time to transition.
  // As the risk is greatest for publicly trusted certificates, prevent
  // those certificates from being trusted from that date forward.
  if (verify_result->has_md5 ||
      (verify_result->has_sha1_leaf && verify_result->is_issued_by_known_root &&
       IsPastSHA1DeprecationDate(*cert))) {
    verify_result->cert_status |= CERT_STATUS_WEAK_SIGNATURE_ALGORITHM;
    // Avoid replacing a more serious error, such as an OS/library failure,
    // by ensuring that if verification failed, it failed with a certificate
    // error.
    if (rv == OK || IsCertificateError(rv))
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  // Flag certificates from publicly-trusted CAs that are issued to intranet
  // hosts. While the CA/Browser Forum Baseline Requirements (v1.1) permit
  // these to be issued until 1 November 2015, they represent a real risk for
  // the deployment of gTLDs and are being phased out ahead of the hard
  // deadline.
  if (verify_result->is_issued_by_known_root && IsHostnameNonUnique(hostname)) {
    verify_result->cert_status |= CERT_STATUS_NON_UNIQUE_NAME;
    // CERT_STATUS_NON_UNIQUE_NAME will eventually become a hard error. For
    // now treat it as a warning and do not map it to an error return value.
  }

  // Flag certificates using too long validity periods.
  if (verify_result->is_issued_by_known_root && HasTooLongValidity(*cert)) {
    verify_result->cert_status |= CERT_STATUS_VALIDITY_TOO_LONG;
    if (rv == OK)
      rv = MapCertStatusToNetError(verify_result->cert_status);
  }

  return rv;
}

// static
bool CertVerifyProc::IsBlacklisted(X509Certificate* cert) {
  // CloudFlare revoked all certificates issued prior to April 2nd, 2014. Thus
  // all certificates where the CN ends with ".cloudflare.com" with a prior
  // issuance date are rejected.
  //
  // The old certs had a lifetime of five years, so this can be removed April
  // 2nd, 2019.
  const std::string& cn = cert->subject().common_name;
  static const char kCloudFlareCNSuffix[] = ".cloudflare.com";
  // kCloudFlareEpoch is the base::Time internal value for midnight at the
  // beginning of April 2nd, 2014, UTC.
  static const int64_t kCloudFlareEpoch = INT64_C(13040870400000000);
  if (cn.size() > arraysize(kCloudFlareCNSuffix) - 1 &&
      cn.compare(cn.size() - (arraysize(kCloudFlareCNSuffix) - 1),
                 arraysize(kCloudFlareCNSuffix) - 1,
                 kCloudFlareCNSuffix) == 0 &&
      cert->valid_start() < base::Time::FromInternalValue(kCloudFlareEpoch)) {
    return true;
  }

  return false;
}

// static
bool CertVerifyProc::IsPublicKeyBlacklisted(
    const HashValueVector& public_key_hashes) {
// Defines kBlacklistedSPKIs.
#include "net/cert/cert_verify_proc_blacklist.inc"
  for (const auto& hash : public_key_hashes) {
    if (hash.tag != HASH_VALUE_SHA256)
      continue;
    if (std::binary_search(std::begin(kBlacklistedSPKIs),
                           std::end(kBlacklistedSPKIs), hash,
                           HashToArrayComparator())) {
      return true;
    }
  }
  return false;
}

static const size_t kMaxDomainLength = 18;

// CheckNameConstraints verifies that every name in |dns_names| is in one of
// the domains specified by |domains|. The |domains| array is terminated by an
// empty string.
static bool CheckNameConstraints(const std::vector<std::string>& dns_names,
                                 const char domains[][kMaxDomainLength]) {
  for (std::vector<std::string>::const_iterator i = dns_names.begin();
       i != dns_names.end(); ++i) {
    bool ok = false;
    url::CanonHostInfo host_info;
    const std::string dns_name = CanonicalizeHost(*i, &host_info);
    if (host_info.IsIPAddress())
      continue;

    const size_t registry_len = registry_controlled_domains::GetRegistryLength(
        dns_name,
        registry_controlled_domains::EXCLUDE_UNKNOWN_REGISTRIES,
        registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES);
    // If the name is not in a known TLD, ignore it. This permits internal
    // names.
    if (registry_len == 0)
      continue;

    for (size_t j = 0; domains[j][0]; ++j) {
      const size_t domain_length = strlen(domains[j]);
      // The DNS name must have "." + domains[j] as a suffix.
      if (i->size() <= (1 /* period before domain */ + domain_length))
        continue;

      std::string suffix =
          base::ToLowerASCII(&(*i)[i->size() - domain_length - 1]);
      if (suffix[0] != '.')
        continue;
      if (memcmp(&suffix[1], domains[j], domain_length) != 0)
        continue;
      ok = true;
      break;
    }

    if (!ok)
      return false;
  }

  return true;
}

// PublicKeyDomainLimitation contains a SHA1, SPKI hash and a pointer to an
// array of fixed-length strings that contain the domains that the SPKI is
// allowed to issue for.
struct PublicKeyDomainLimitation {
  uint8_t public_key[base::kSHA1Length];
  const char (*domains)[kMaxDomainLength];
};

// static
bool CertVerifyProc::HasNameConstraintsViolation(
    const HashValueVector& public_key_hashes,
    const std::string& common_name,
    const std::vector<std::string>& dns_names,
    const std::vector<std::string>& ip_addrs) {
  static const char kDomainsANSSI[][kMaxDomainLength] = {
    "fr",  // France
    "gp",  // Guadeloupe
    "gf",  // Guyane
    "mq",  // Martinique
    "re",  // Réunion
    "yt",  // Mayotte
    "pm",  // Saint-Pierre et Miquelon
    "bl",  // Saint Barthélemy
    "mf",  // Saint Martin
    "wf",  // Wallis et Futuna
    "pf",  // Polynésie française
    "nc",  // Nouvelle Calédonie
    "tf",  // Terres australes et antarctiques françaises
    "",
  };

  static const char kDomainsIndiaCCA[][kMaxDomainLength] = {
    "gov.in",
    "nic.in",
    "ac.in",
    "rbi.org.in",
    "bankofindia.co.in",
    "ncode.in",
    "tcs.co.in",
    "",
  };

  static const char kDomainsTest[][kMaxDomainLength] = {
    "example.com",
    "",
  };

  static const PublicKeyDomainLimitation kLimits[] = {
      // C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI,
      // CN=IGC/A/emailAddress=igca@sgdn.pm.gouv.fr
      {
          {0x79, 0x23, 0xd5, 0x8d, 0x0f, 0xe0, 0x3c, 0xe6, 0xab, 0xad, 0xae,
           0x27, 0x1a, 0x6d, 0x94, 0xf4, 0x14, 0xd1, 0xa8, 0x73},
          kDomainsANSSI,
      },
      // C=IN, O=India PKI, CN=CCA India 2007
      // Expires: July 4th 2015.
      {
          {0xfe, 0xe3, 0x95, 0x21, 0x2d, 0x5f, 0xea, 0xfc, 0x7e, 0xdc, 0xcf,
           0x88, 0x3f, 0x1e, 0xc0, 0x58, 0x27, 0xd8, 0xb8, 0xe4},
          kDomainsIndiaCCA,
      },
      // C=IN, O=India PKI, CN=CCA India 2011
      // Expires: March 11 2016.
      {
          {0xf1, 0x42, 0xf6, 0xa2, 0x7d, 0x29, 0x3e, 0xa8, 0xf9, 0x64, 0x52,
           0x56, 0xed, 0x07, 0xa8, 0x63, 0xf2, 0xdb, 0x1c, 0xdf},
          kDomainsIndiaCCA,
      },
      // C=IN, O=India PKI, CN=CCA India 2014
      // Expires: March 5 2024.
      {
          {0x36, 0x8c, 0x4a, 0x1e, 0x2d, 0xb7, 0x81, 0xe8, 0x6b, 0xed, 0x5a,
           0x0a, 0x42, 0xb8, 0xc5, 0xcf, 0x6d, 0xb3, 0x57, 0xe1},
          kDomainsIndiaCCA,
      },
      // Not a real certificate - just for testing. This is the SPKI hash of
      // the keys used in net/data/ssl/certificates/name_constraint_*.crt.
      {
          {0x48, 0x49, 0x4a, 0xc5, 0x5a, 0x3e, 0xcd, 0xc5, 0x62, 0x9f, 0xef,
           0x23, 0x14, 0xad, 0x05, 0xa9, 0x2a, 0x5c, 0x39, 0xc0},
          kDomainsTest,
      },
  };

  for (unsigned i = 0; i < arraysize(kLimits); ++i) {
    for (HashValueVector::const_iterator j = public_key_hashes.begin();
         j != public_key_hashes.end(); ++j) {
      if (j->tag == HASH_VALUE_SHA1 &&
          memcmp(j->data(), kLimits[i].public_key, base::kSHA1Length) == 0) {
        if (dns_names.empty() && ip_addrs.empty()) {
          std::vector<std::string> dns_names;
          dns_names.push_back(common_name);
          if (!CheckNameConstraints(dns_names, kLimits[i].domains))
            return true;
        } else {
          if (!CheckNameConstraints(dns_names, kLimits[i].domains))
            return true;
        }
      }
    }
  }

  return false;
}

// static
bool CertVerifyProc::HasTooLongValidity(const X509Certificate& cert) {
  const base::Time& start = cert.valid_start();
  const base::Time& expiry = cert.valid_expiry();
  if (start.is_max() || start.is_null() || expiry.is_max() ||
      expiry.is_null() || start > expiry) {
    return true;
  }

  base::Time::Exploded exploded_start;
  base::Time::Exploded exploded_expiry;
  cert.valid_start().UTCExplode(&exploded_start);
  cert.valid_expiry().UTCExplode(&exploded_expiry);

  if (exploded_expiry.year - exploded_start.year > 10)
    return true;

  int month_diff = (exploded_expiry.year - exploded_start.year) * 12 +
                   (exploded_expiry.month - exploded_start.month);

  // Add any remainder as a full month.
  if (exploded_expiry.day_of_month > exploded_start.day_of_month)
    ++month_diff;

  static const base::Time time_2012_07_01 =
      base::Time::FromUTCExploded({2012, 7, 0, 1, 0, 0, 0, 0});
  static const base::Time time_2015_04_01 =
      base::Time::FromUTCExploded({2015, 4, 0, 1, 0, 0, 0, 0});
  static const base::Time time_2019_07_01 =
      base::Time::FromUTCExploded({2019, 7, 0, 1, 0, 0, 0, 0});

  // For certificates issued before the BRs took effect.
  if (start < time_2012_07_01 && (month_diff > 120 || expiry > time_2019_07_01))
    return true;

  // For certificates issued after 1 July 2012: 60 months.
  if (start >= time_2012_07_01 && month_diff > 60)
    return true;

  // For certificates issued after 1 April 2015: 39 months.
  if (start >= time_2015_04_01 && month_diff > 39)
    return true;

  return false;
}

}  // namespace net
