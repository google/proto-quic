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
#include "base/memory/ptr_util.h"
#include "base/strings/sys_string_conversions.h"
#include "base/synchronization/lock.h"
#include "crypto/mac_security_services_lock.h"
#include "net/base/host_port_pair.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_ios_and_mac.h"
#include "net/cert/x509_util_mac.h"
#include "net/ssl/client_cert_identity_mac.h"

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

// Returns true if |*identity| is issued by an authority in |valid_issuers|
// according to Keychain Services, rather than using |identity|'s intermediate
// certificates. If it is, |*identity| is updated to include the intermediates.
bool IsIssuedByInKeychain(const std::vector<std::string>& valid_issuers,
                          ClientCertIdentity* identity) {
  DCHECK(identity);
  DCHECK(identity->sec_identity_ref());

  ScopedCFTypeRef<SecCertificateRef> os_cert;
  int err = SecIdentityCopyCertificate(identity->sec_identity_ref(),
                                       os_cert.InitializeInto());
  if (err != noErr)
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
    SecCertificateRef sec_cert = reinterpret_cast<SecCertificateRef>(
        const_cast<void*>(CFArrayGetValueAtIndex(cert_chain, i)));
    intermediates.push_back(sec_cert);
  }

  scoped_refptr<X509Certificate> new_cert(
      x509_util::CreateX509CertificateFromSecCertificate(os_cert.get(),
                                                         intermediates));
  CFRelease(cert_chain);  // Also frees |intermediates|.

  if (!new_cert || !new_cert->IsIssuedByEncoded(valid_issuers))
    return false;

  identity->SetIntermediates(new_cert->GetIntermediateCertificates());
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

// Examines the certificates in |preferred_identity| and |regular_identities| to
// find all certificates that match the client certificate request in |request|,
// storing the matching certificates in |selected_identities|.
// If |query_keychain| is true, Keychain Services will be queried to construct
// full certificate chains. If it is false, only the the certificates and their
// intermediates (available via X509Certificate::GetIntermediateCertificates())
// will be considered.
void GetClientCertsImpl(std::unique_ptr<ClientCertIdentity> preferred_identity,
                        ClientCertIdentityList regular_identities,
                        const SSLCertRequestInfo& request,
                        bool query_keychain,
                        ClientCertIdentityList* selected_identities) {
  scoped_refptr<X509Certificate> preferred_cert_orig;
  ClientCertIdentityList preliminary_list(std::move(regular_identities));
  if (preferred_identity) {
    preferred_cert_orig = preferred_identity->certificate();
    preliminary_list.insert(preliminary_list.begin(),
                            std::move(preferred_identity));
  }

  selected_identities->clear();
  for (size_t i = 0; i < preliminary_list.size(); ++i) {
    std::unique_ptr<ClientCertIdentity>& cert = preliminary_list[i];
    if (cert->certificate()->HasExpired())
      continue;

    // Skip duplicates (a cert may be in multiple keychains).
    auto cert_iter = std::find_if(
        selected_identities->begin(), selected_identities->end(),
        [&cert](
            const std::unique_ptr<ClientCertIdentity>& other_cert_identity) {
          return X509Certificate::IsSameOSCert(
              cert->certificate()->os_cert_handle(),
              other_cert_identity->certificate()->os_cert_handle());
        });
    if (cert_iter != selected_identities->end())
      continue;

    // Check if the certificate issuer is allowed by the server.
    if (request.cert_authorities.empty() ||
        cert->certificate()->IsIssuedByEncoded(request.cert_authorities) ||
        (query_keychain &&
         IsIssuedByInKeychain(request.cert_authorities, cert.get()))) {
      selected_identities->push_back(std::move(cert));
    }
  }

  // Preferred cert should appear first in the ui, so exclude it from the
  // sorting.  Compare the os_cert_handle since the X509Certificate object may
  // have changed if intermediates were added.
  ClientCertIdentityList::iterator sort_begin = selected_identities->begin();
  ClientCertIdentityList::iterator sort_end = selected_identities->end();
  if (preferred_cert_orig && sort_begin != sort_end &&
      X509Certificate::IsSameOSCert(
          sort_begin->get()->certificate()->os_cert_handle(),
          preferred_cert_orig->os_cert_handle())) {
    ++sort_begin;
  }
  sort(sort_begin, sort_end, ClientCertIdentitySorter());
}

}  // namespace

ClientCertStoreMac::ClientCertStoreMac() {}

ClientCertStoreMac::~ClientCertStoreMac() {}

void ClientCertStoreMac::GetClientCerts(
    const SSLCertRequestInfo& request,
    const ClientCertListCallback& callback) {
  std::string server_domain = request.host_and_port.host();

  ScopedCFTypeRef<SecIdentityRef> preferred_sec_identity;
  if (!server_domain.empty()) {
    // See if there's an identity preference for this domain:
    ScopedCFTypeRef<CFStringRef> domain_str(
        base::SysUTF8ToCFStringRef("https://" + server_domain));
    SecIdentityRef sec_identity = NULL;
    // While SecIdentityCopyPreferences appears to take a list of CA issuers
    // to restrict the identity search to, within Security.framework the
    // argument is ignored and filtering unimplemented. See
    // SecIdentity.cpp in libsecurity_keychain, specifically
    // _SecIdentityCopyPreferenceMatchingName().
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      if (SecIdentityCopyPreference(domain_str, 0, NULL, &sec_identity) ==
          noErr)
        preferred_sec_identity.reset(sec_identity);
    }
  }

  // Now enumerate the identities in the available keychains.
  std::unique_ptr<ClientCertIdentity> preferred_identity;
  ClientCertIdentityList regular_identities;

  SecIdentitySearchRef search = NULL;
  OSStatus err;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    err = SecIdentitySearchCreate(NULL, CSSM_KEYUSE_SIGN, &search);
  }
  if (err) {
    callback.Run(ClientCertIdentityList());
    return;
  }
  ScopedCFTypeRef<SecIdentitySearchRef> scoped_search(search);
  while (!err) {
    ScopedCFTypeRef<SecIdentityRef> sec_identity;
    {
      base::AutoLock lock(crypto::GetMacSecurityServicesLock());
      err = SecIdentitySearchCopyNext(search, sec_identity.InitializeInto());
    }
    if (err)
      break;

    ScopedCFTypeRef<SecCertificateRef> cert_handle;
    err = SecIdentityCopyCertificate(sec_identity.get(),
                                     cert_handle.InitializeInto());
    if (err != noErr)
      continue;

    if (!SupportsSSLClientAuth(cert_handle.get()))
      continue;

    scoped_refptr<X509Certificate> cert(
        x509_util::CreateX509CertificateFromSecCertificate(
            cert_handle.get(), std::vector<SecCertificateRef>()));
    if (!cert)
      continue;

    if (preferred_sec_identity &&
        CFEqual(preferred_sec_identity, sec_identity.get())) {
      // Only one certificate should match.
      DCHECK(!preferred_identity.get());
      preferred_identity = base::MakeUnique<ClientCertIdentityMac>(
          std::move(cert), std::move(sec_identity));
    } else {
      regular_identities.push_back(base::MakeUnique<ClientCertIdentityMac>(
          std::move(cert), std::move(sec_identity)));
    }
  }

  if (err != errSecItemNotFound) {
    OSSTATUS_LOG(ERROR, err) << "SecIdentitySearch error";
    callback.Run(ClientCertIdentityList());
    return;
  }

  ClientCertIdentityList selected_identities;
  GetClientCertsImpl(std::move(preferred_identity),
                     std::move(regular_identities), request, true,
                     &selected_identities);
  callback.Run(std::move(selected_identities));
}

bool ClientCertStoreMac::SelectClientCertsForTesting(
    ClientCertIdentityList input_identities,
    const SSLCertRequestInfo& request,
    ClientCertIdentityList* selected_identities) {
  GetClientCertsImpl(NULL, std::move(input_identities), request, false,
                     selected_identities);
  return true;
}

bool ClientCertStoreMac::SelectClientCertsGivenPreferredForTesting(
    std::unique_ptr<ClientCertIdentity> preferred_identity,
    ClientCertIdentityList regular_identities,
    const SSLCertRequestInfo& request,
    ClientCertIdentityList* selected_identities) {
  GetClientCertsImpl(std::move(preferred_identity),
                     std::move(regular_identities), request, false,
                     selected_identities);
  return true;
}

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"

}  // namespace net
