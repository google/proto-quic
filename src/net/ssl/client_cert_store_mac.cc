// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_cert_store_mac.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CFArray.h>
#include <CoreServices/CoreServices.h>
#include <Security/SecBase.h>
#include <Security/Security.h>

#include <algorithm>
#include <string>

#include "base/callback.h"
#include "base/logging.h"
#include "base/mac/mac_logging.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/strings/sys_string_conversions.h"
#include "base/synchronization/lock.h"
#include "crypto/mac_security_services_lock.h"
#include "net/base/host_port_pair.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_ios_and_mac.h"
#include "net/cert/x509_util_mac.h"

using base::ScopedCFTypeRef;

namespace net {

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

namespace {

// Gets the issuer for a given cert, starting with the cert itself and
// including the intermediate and finally root certificates (if any).
// This function calls SecTrust but doesn't actually pay attention to the trust
// result: it shouldn't be used to determine trust, just to traverse the chain.
// Caller is responsible for releasing the value stored into *out_cert_chain.
OSStatus CopyCertChain(SecCertificateRef cert_handle,
                       CFArrayRef* out_cert_chain) {
  DCHECK(cert_handle);
  DCHECK(out_cert_chain);

  // Create an SSL policy ref configured for client cert evaluation.
  SecPolicyRef ssl_policy;
  OSStatus result = x509_util::CreateSSLClientPolicy(&ssl_policy);
  if (result)
    return result;
  ScopedCFTypeRef<SecPolicyRef> scoped_ssl_policy(ssl_policy);

  // Create a SecTrustRef.
  ScopedCFTypeRef<CFArrayRef> input_certs(CFArrayCreate(
      NULL, const_cast<const void**>(reinterpret_cast<void**>(&cert_handle)),
      1, &kCFTypeArrayCallBacks));
  SecTrustRef trust_ref = NULL;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    result = SecTrustCreateWithCertificates(input_certs, ssl_policy,
                                            &trust_ref);
  }
  if (result)
    return result;
  ScopedCFTypeRef<SecTrustRef> trust(trust_ref);

  // Evaluate trust, which creates the cert chain.
  SecTrustResultType status;
  CSSM_TP_APPLE_EVIDENCE_INFO* status_chain;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    result = SecTrustEvaluate(trust, &status);
  }
  if (result)
    return result;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    result = SecTrustGetResult(trust, &status, out_cert_chain, &status_chain);
  }
  return result;
}

// Returns true if |*cert| is issued by an authority in |valid_issuers|
// according to Keychain Services, rather than using |cert|'s intermediate
// certificates. If it is, |*cert| is updated to point to the completed
// certificate
bool IsIssuedByInKeychain(const std::vector<std::string>& valid_issuers,
                          scoped_refptr<X509Certificate>* cert) {
  DCHECK(cert);
  DCHECK(cert->get());

  base::ScopedCFTypeRef<SecCertificateRef> os_cert(
      x509_util::CreateSecCertificateFromX509Certificate(cert->get()));
  if (!os_cert)
    return false;
  CFArrayRef cert_chain = NULL;
  OSStatus result = CopyCertChain(os_cert.get(), &cert_chain);
  if (result) {
    OSSTATUS_LOG(ERROR, result) << "CopyCertChain error";
    return false;
  }

  if (!cert_chain)
    return false;

  std::vector<SecCertificateRef> intermediates;
  for (CFIndex i = 1, chain_count = CFArrayGetCount(cert_chain);
       i < chain_count; ++i) {
    SecCertificateRef cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(cert_chain, i)));
    intermediates.push_back(cert);
  }

  scoped_refptr<X509Certificate> new_cert(
      x509_util::CreateX509CertificateFromSecCertificate(os_cert.get(),
                                                         intermediates));
  CFRelease(cert_chain);  // Also frees |intermediates|.

  if (!new_cert || !new_cert->IsIssuedByEncoded(valid_issuers))
    return false;

  cert->swap(new_cert);
  return true;
}

// Returns true if |purpose| is listed as allowed in |usage|. This
// function also considers the "Any" purpose. If the attribute is
// present and empty, we return false.
bool ExtendedKeyUsageAllows(const CE_ExtendedKeyUsage* usage,
                            const CSSM_OID* purpose) {
  for (unsigned p = 0; p < usage->numPurposes; ++p) {
    if (CSSMOIDEqual(&usage->purposes[p], purpose))
      return true;
    if (CSSMOIDEqual(&usage->purposes[p], &CSSMOID_ExtendedKeyUsageAny))
      return true;
  }
  return false;
}

// Does |cert|'s usage allow SSL client authentication?
bool SupportsSSLClientAuth(SecCertificateRef cert) {
  x509_util::CSSMCachedCertificate cached_cert;
  OSStatus status = cached_cert.Init(cert);
  if (status)
    return false;

  // RFC5280 says to take the intersection of the two extensions.
  //
  // Our underlying crypto libraries don't expose
  // ClientCertificateType, so for now we will not support fixed
  // Diffie-Hellman mechanisms. For rsa_sign, we need the
  // digitalSignature bit.
  //
  // In particular, if a key has the nonRepudiation bit and not the
  // digitalSignature one, we will not offer it to the user.
  x509_util::CSSMFieldValue key_usage;
  status = cached_cert.GetField(&CSSMOID_KeyUsage, &key_usage);
  if (status == CSSM_OK && key_usage.field()) {
    const CSSM_X509_EXTENSION* ext = key_usage.GetAs<CSSM_X509_EXTENSION>();
    const CE_KeyUsage* key_usage_value =
        reinterpret_cast<const CE_KeyUsage*>(ext->value.parsedValue);
    if (!((*key_usage_value) & CE_KU_DigitalSignature))
      return false;
  }

  status = cached_cert.GetField(&CSSMOID_ExtendedKeyUsage, &key_usage);
  if (status == CSSM_OK && key_usage.field()) {
    const CSSM_X509_EXTENSION* ext = key_usage.GetAs<CSSM_X509_EXTENSION>();
    const CE_ExtendedKeyUsage* ext_key_usage =
        reinterpret_cast<const CE_ExtendedKeyUsage*>(ext->value.parsedValue);
    if (!ExtendedKeyUsageAllows(ext_key_usage, &CSSMOID_ClientAuth))
      return false;
  }
  return true;
}

// Examines the certificates in |preferred_cert| and |regular_certs| to find
// all certificates that match the client certificate request in |request|,
// storing the matching certificates in |selected_certs|.
// If |query_keychain| is true, Keychain Services will be queried to construct
// full certificate chains. If it is false, only the the certificates and their
// intermediates (available via X509Certificate::GetIntermediateCertificates())
// will be considered.
void GetClientCertsImpl(const scoped_refptr<X509Certificate>& preferred_cert,
                        const CertificateList& regular_certs,
                        const SSLCertRequestInfo& request,
                        bool query_keychain,
                        CertificateList* selected_certs) {
  CertificateList preliminary_list;
  if (preferred_cert.get())
    preliminary_list.push_back(preferred_cert);
  preliminary_list.insert(preliminary_list.end(), regular_certs.begin(),
                          regular_certs.end());

  selected_certs->clear();
  for (size_t i = 0; i < preliminary_list.size(); ++i) {
    scoped_refptr<X509Certificate>& cert = preliminary_list[i];
    if (cert->HasExpired())
      continue;

    // Skip duplicates (a cert may be in multiple keychains).
    auto cert_iter = std::find_if(
        selected_certs->begin(), selected_certs->end(),
        [&cert](const scoped_refptr<X509Certificate>& other_cert) {
          return X509Certificate::IsSameOSCert(cert->os_cert_handle(),
                                               other_cert->os_cert_handle());
        });
    if (cert_iter != selected_certs->end())
      continue;

    // Check if the certificate issuer is allowed by the server.
    if (request.cert_authorities.empty() ||
        cert->IsIssuedByEncoded(request.cert_authorities) ||
        (query_keychain &&
         IsIssuedByInKeychain(request.cert_authorities, &cert))) {
      selected_certs->push_back(cert);
    }
  }

  // Preferred cert should appear first in the ui, so exclude it from the
  // sorting.
  CertificateList::iterator sort_begin = selected_certs->begin();
  CertificateList::iterator sort_end = selected_certs->end();
  if (preferred_cert.get() && sort_begin != sort_end &&
      sort_begin->get() == preferred_cert.get()) {
    ++sort_begin;
  }
  sort(sort_begin, sort_end, x509_util::ClientCertSorter());
}

}  // namespace

ClientCertStoreMac::ClientCertStoreMac() {}

ClientCertStoreMac::~ClientCertStoreMac() {}

void ClientCertStoreMac::GetClientCerts(
    const SSLCertRequestInfo& request,
    const ClientCertListCallback& callback) {
  std::string server_domain = request.host_and_port.host();

  ScopedCFTypeRef<SecIdentityRef> preferred_identity;
  if (!server_domain.empty()) {
    // See if there's an identity preference for this domain:
    ScopedCFTypeRef<CFStringRef> domain_str(
        base::SysUTF8ToCFStringRef("https://" + server_domain));
    SecIdentityRef identity = NULL;
    // While SecIdentityCopyPreferences appears to take a list of CA issuers
    // to restrict the identity search to, within Security.framework the
    // argument is ignored and filtering unimplemented. See
    // SecIdentity.cpp in libsecurity_keychain, specifically
    // _SecIdentityCopyPreferenceMatchingName().
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      if (SecIdentityCopyPreference(domain_str, 0, NULL, &identity) == noErr)
        preferred_identity.reset(identity);
    }
  }

  // Now enumerate the identities in the available keychains.
  scoped_refptr<X509Certificate> preferred_cert = NULL;
  CertificateList regular_certs;

  SecIdentitySearchRef search = NULL;
  OSStatus err;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    err = SecIdentitySearchCreate(NULL, CSSM_KEYUSE_SIGN, &search);
  }
  if (err) {
    callback.Run(CertificateList());
    return;
  }
  ScopedCFTypeRef<SecIdentitySearchRef> scoped_search(search);
  while (!err) {
    SecIdentityRef identity = NULL;
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      err = SecIdentitySearchCopyNext(search, &identity);
    }
    if (err)
      break;
    ScopedCFTypeRef<SecIdentityRef> scoped_identity(identity);

    SecCertificateRef cert_handle;
    err = SecIdentityCopyCertificate(identity, &cert_handle);
    if (err != noErr)
      continue;
    ScopedCFTypeRef<SecCertificateRef> scoped_cert_handle(cert_handle);

    if (!SupportsSSLClientAuth(cert_handle))
      continue;

    scoped_refptr<X509Certificate> cert(
        x509_util::CreateX509CertificateFromSecCertificate(
            cert_handle, std::vector<SecCertificateRef>()));
    if (!cert)
      continue;

    if (preferred_identity && CFEqual(preferred_identity, identity)) {
      // Only one certificate should match.
      DCHECK(!preferred_cert.get());
      preferred_cert = cert;
    } else {
      regular_certs.push_back(cert);
    }
  }

  if (err != errSecItemNotFound) {
    OSSTATUS_LOG(ERROR, err) << "SecIdentitySearch error";
    callback.Run(CertificateList());
    return;
  }

  CertificateList selected_certs;
  GetClientCertsImpl(preferred_cert, regular_certs, request, true,
                     &selected_certs);
  callback.Run(std::move(selected_certs));
}

bool ClientCertStoreMac::SelectClientCertsForTesting(
    const CertificateList& input_certs,
    const SSLCertRequestInfo& request,
    CertificateList* selected_certs) {
  GetClientCertsImpl(NULL, input_certs, request, false, selected_certs);
  return true;
}

bool ClientCertStoreMac::SelectClientCertsGivenPreferredForTesting(
    const scoped_refptr<X509Certificate>& preferred_cert,
    const CertificateList& regular_certs,
    const SSLCertRequestInfo& request,
    CertificateList* selected_certs) {
  GetClientCertsImpl(
      preferred_cert, regular_certs, request, false, selected_certs);
  return true;
}

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"

}  // namespace net
