// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_builtin.h"

#include <string>
#include <vector>

#if defined(USE_NSS_CERTS)
#include <cert.h>
#include <pk11pub.h>
#endif

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/sha1.h"
#include "base/strings/string_piece.h"
#include "crypto/sha2.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/cert_issuer_source_static.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/path_builder.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store_collection.h"
#include "net/cert/internal/trust_store_in_memory.h"
#include "net/cert/internal/verify_certificate_chain.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/der/encode_values.h"

#if defined(USE_NSS_CERTS)
#include "crypto/nss_util.h"
#include "net/cert/internal/cert_issuer_source_nss.h"
#include "net/cert/internal/trust_store_nss.h"
#include "net/cert/scoped_nss_types.h"
#endif

namespace net {

namespace {

class CertVerifyProcBuiltin : public CertVerifyProc {
 public:
  CertVerifyProcBuiltin();

  bool SupportsAdditionalTrustAnchors() const override;
  bool SupportsOCSPStapling() const override;

 protected:
  ~CertVerifyProcBuiltin() override;

 private:
  int VerifyInternal(X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     int flags,
                     CRLSet* crl_set,
                     const CertificateList& additional_trust_anchors,
                     CertVerifyResult* verify_result) override;
};

CertVerifyProcBuiltin::CertVerifyProcBuiltin() {}

CertVerifyProcBuiltin::~CertVerifyProcBuiltin() {}

bool CertVerifyProcBuiltin::SupportsAdditionalTrustAnchors() const {
  return true;
}

bool CertVerifyProcBuiltin::SupportsOCSPStapling() const {
  // TODO(crbug.com/649017): Implement.
  return false;
}

scoped_refptr<ParsedCertificate> ParseCertificateFromOSHandle(
    X509Certificate::OSCertHandle cert_handle,
    CertErrors* errors) {
  std::string cert_bytes;
  if (!X509Certificate::GetDEREncoded(cert_handle, &cert_bytes))
    return nullptr;
  return ParsedCertificate::Create(x509_util::CreateCryptoBuffer(cert_bytes),
                                   {}, errors);
}

void AddIntermediatesToIssuerSource(X509Certificate* x509_cert,
                                    CertIssuerSourceStatic* intermediates) {
  const X509Certificate::OSCertHandles& cert_handles =
      x509_cert->GetIntermediateCertificates();
  CertErrors errors;
  for (auto it = cert_handles.begin(); it != cert_handles.end(); ++it) {
    scoped_refptr<ParsedCertificate> cert =
        ParseCertificateFromOSHandle(*it, &errors);
    if (cert)
      intermediates->AddCert(std::move(cert));
    // TODO(crbug.com/634443): Surface these parsing errors?
  }
}

// The SystemTrustStore interface augments the TrustStore interface with some
// additional functionality:
//
//  * Determine if a trust anchor was one of the known roots
//  * Determine if a trust anchor was one of the "extra" ones that
//    was specified during verification.
//
// Implementations of SystemTrustStore create an effective trust
// store that is the composition of:
//
//  (1) System trust store
//  (2) |additional_trust_anchors|.
//  (3) Test certificates (if they are separate from system trust store)
class SystemTrustStore {
 public:
  virtual ~SystemTrustStore() {}

  virtual TrustStore* GetTrustStore() = 0;

  // TODO(eroman): Can this be exposed through the TrustStore
  //               interface instead?
  virtual CertIssuerSource* GetCertIssuerSource() = 0;

  // IsKnownRoot returns true if the given trust anchor is a standard one (as
  // opposed to a user-installed root)
  virtual bool IsKnownRoot(
      const scoped_refptr<TrustAnchor>& trust_anchor) const = 0;

  virtual bool IsAdditionalTrustAnchor(
      const scoped_refptr<TrustAnchor>& trust_anchor) const = 0;
};

#if defined(USE_NSS_CERTS)
class SystemTrustStoreNSS : public SystemTrustStore {
 public:
  explicit SystemTrustStoreNSS(const CertificateList& additional_trust_anchors)
      : trust_store_nss_(trustSSL) {
    CertErrors errors;

    trust_store_.AddTrustStore(&additional_trust_store_);
    for (const auto& x509_cert : additional_trust_anchors) {
      scoped_refptr<ParsedCertificate> cert =
          ParseCertificateFromOSHandle(x509_cert->os_cert_handle(), &errors);
      if (cert) {
        additional_trust_store_.AddTrustAnchor(
            TrustAnchor::CreateFromCertificateNoConstraints(std::move(cert)));
      }
      // TODO(eroman): Surface parsing errors of additional trust anchor.
    }

    trust_store_.AddTrustStore(&trust_store_nss_);
  }

  TrustStore* GetTrustStore() override { return &trust_store_; }

  CertIssuerSource* GetCertIssuerSource() override {
    return &cert_issuer_source_nss_;
  }

  // IsKnownRoot returns true if the given trust anchor is a standard one (as
  // opposed to a user-installed root)
  bool IsKnownRoot(
      const scoped_refptr<TrustAnchor>& trust_anchor) const override {
    // TODO(eroman): Based on how the TrustAnchors are created by this
    // integration, there will always be an associated certificate. However this
    // contradicts the API for TrustAnchor that states it is optional.
    DCHECK(trust_anchor->cert());

    // TODO(eroman): The overall approach of IsKnownRoot() is inefficient -- it
    // requires searching for the trust anchor by DER in NSS, however path
    // building already had a handle to it.
    SECItem der_cert;
    der_cert.data =
        const_cast<uint8_t*>(trust_anchor->cert()->der_cert().UnsafeData());
    der_cert.len = trust_anchor->cert()->der_cert().Length();
    der_cert.type = siDERCertBuffer;
    ScopedCERTCertificate nss_cert(
        CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &der_cert));
    if (!nss_cert)
      return false;

    return IsKnownRoot(nss_cert.get());
  }

  bool IsAdditionalTrustAnchor(
      const scoped_refptr<TrustAnchor>& trust_anchor) const override {
    return additional_trust_store_.Contains(trust_anchor.get());
  }

 private:
  // TODO(eroman): This function was copied verbatim from
  // cert_verify_proc_nss.cc
  //
  // IsKnownRoot returns true if the given certificate is one that we believe
  // is a standard (as opposed to user-installed) root.
  bool IsKnownRoot(CERTCertificate* root) const {
    if (!root || !root->slot)
      return false;

    // This magic name is taken from
    // http://bonsai.mozilla.org/cvsblame.cgi?file=mozilla/security/nss/lib/ckfw/builtins/constants.c&rev=1.13&mark=86,89#79
    return 0 == strcmp(PK11_GetSlotName(root->slot), "NSS Builtin Objects");
  }

  TrustStoreCollection trust_store_;
  TrustStoreInMemory additional_trust_store_;

  TrustStoreNSS trust_store_nss_;
  CertIssuerSourceNSS cert_issuer_source_nss_;
};
#endif

std::unique_ptr<SystemTrustStore> CreateSystemTrustStore(
    const CertificateList& additional_trust_anchors) {
#if defined(USE_NSS_CERTS)
  return base::MakeUnique<SystemTrustStoreNSS>(additional_trust_anchors);
#else
  // TODO(crbug.com/649017): Integrate with other system trust stores.
  NOTIMPLEMENTED();
  return nullptr;
#endif
}

// Appends the SHA1 and SHA256 hashes of |spki_bytes| to |*hashes|.
void AppendPublicKeyHashes(const der::Input& spki_bytes,
                           HashValueVector* hashes) {
  HashValue sha1(HASH_VALUE_SHA1);
  base::SHA1HashBytes(spki_bytes.UnsafeData(), spki_bytes.Length(),
                      sha1.data());
  hashes->push_back(sha1);

  HashValue sha256(HASH_VALUE_SHA256);
  crypto::SHA256HashString(spki_bytes.AsStringPiece(), sha256.data(),
                           crypto::kSHA256Length);
  hashes->push_back(sha256);
}

// Appends the SubjectPublicKeyInfo hashes for all certificates (and trust
// anchor) in |partial_path| to |*hashes|.
void AppendPublicKeyHashes(const CertPathBuilder::ResultPath& partial_path,
                           HashValueVector* hashes) {
  for (const scoped_refptr<ParsedCertificate>& cert : partial_path.path.certs)
    AppendPublicKeyHashes(cert->tbs().spki_tlv, hashes);

  if (partial_path.path.trust_anchor)
    AppendPublicKeyHashes(partial_path.path.trust_anchor->spki(), hashes);
}

// Sets the bits on |cert_status| for all the errors encountered during the path
// building of |partial_path|.
void MapPathBuilderErrorsToCertStatus(
    const CertPathBuilder::ResultPath& partial_path,
    const std::string& hostname,
    CertStatus* cert_status) {
  // If path building was successful, there are no errors to map (there may have
  // been warnings but they do not map to CertStatus).
  if (partial_path.valid)
    return;

  LOG(ERROR) << "CertVerifyProcBuiltin for " << hostname << " failed:\n"
             << partial_path.errors.ToDebugString();

  if (partial_path.errors.ContainsError(kRsaModulusTooSmall))
    *cert_status |= CERT_STATUS_WEAK_KEY;

  if (partial_path.errors.ContainsError(kValidityFailedNotAfter) ||
      partial_path.errors.ContainsError(kValidityFailedNotBefore)) {
    *cert_status |= CERT_STATUS_DATE_INVALID;
  }

  // IMPORTANT: If the path was invalid for a reason that was not
  // explicity checked above, set a general error. This is important as
  // |cert_status| is what ultimately indicates whether verification was
  // successful or not (absense of errors implies success).
  if (!IsCertStatusError(*cert_status))
    *cert_status |= CERT_STATUS_INVALID;
}

X509Certificate::OSCertHandle CreateOSCertHandle(
    const scoped_refptr<ParsedCertificate>& certificate) {
  return X509Certificate::CreateOSCertHandleFromBytes(
      reinterpret_cast<const char*>(certificate->der_cert().UnsafeData()),
      certificate->der_cert().Length());
}

// Creates a X509Certificate (chain) to return as the verified result.
//
//  * |target_cert|: The original X509Certificate that was passed in to
//                   VerifyInternal()
//  * |path|: The result (possibly failed) from path building.
scoped_refptr<X509Certificate> CreateVerifiedCertChain(
    X509Certificate* target_cert,
    const CertPathBuilder::ResultPath& path) {
  X509Certificate::OSCertHandles intermediates;

  // Skip the first certificate in the path as that is the target certificate
  for (size_t i = 1; i < path.path.certs.size(); ++i)
    intermediates.push_back(CreateOSCertHandle(path.path.certs[i]));

  if (path.path.trust_anchor) {
    // TODO(eroman): This assumes that TrustAnchor::cert() cannot be null,
    //               which disagrees with the documentation.
    intermediates.push_back(CreateOSCertHandle(path.path.trust_anchor->cert()));
  }

  scoped_refptr<X509Certificate> result = X509Certificate::CreateFromHandle(
      target_cert->os_cert_handle(), intermediates);

  for (const X509Certificate::OSCertHandle handle : intermediates)
    X509Certificate::FreeOSCertHandle(handle);

  return result;
}

// TODO(crbug.com/649017): Make use of |flags|, |crl_set|, and |ocsp_response|.
// Also handle key usages, policies and EV.
//
// Any failure short-circuits from the function must set
// |verify_result->cert_status|.
void DoVerify(X509Certificate* input_cert,
              const std::string& hostname,
              const std::string& ocsp_response,
              int flags,
              CRLSet* crl_set,
              const CertificateList& additional_trust_anchors,
              CertVerifyResult* verify_result) {
  CertErrors errors;

  // Parse the target certificate.
  scoped_refptr<ParsedCertificate> target =
      ParseCertificateFromOSHandle(input_cert->os_cert_handle(), &errors);
  if (!target) {
    // TODO(crbug.com/634443): Surface these parsing errors?
    verify_result->cert_status |= CERT_STATUS_INVALID;
    return;
  }

  std::unique_ptr<SystemTrustStore> trust_store =
      CreateSystemTrustStore(additional_trust_anchors);

  // TODO(eroman): The path building code in this file enforces its idea of weak
  // keys, and separately cert_verify_proc.cc also checks the chains with its
  // own policy. These policies should be aligned, to give path building the
  // best chance of finding a good path.
  // Another difference to resolve is the path building here does not check the
  // target certificate's key strength, whereas cert_verify_proc.cc does.
  SimpleSignaturePolicy signature_policy(1024);

  // Use the current time.
  der::GeneralizedTime verification_time;
  if (!der::EncodeTimeAsGeneralizedTime(base::Time::Now(),
                                        &verification_time)) {
    // This really shouldn't be possible unless Time::Now() returned
    // something crazy.
    verify_result->cert_status |= CERT_STATUS_DATE_INVALID;
    return;
  }

  // Initialize the path builder.
  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target, trust_store->GetTrustStore(),
                               &signature_policy, verification_time, &result);

  // Allow the path builder to discover intermediates from the trust store.
  if (trust_store->GetCertIssuerSource())
    path_builder.AddCertIssuerSource(trust_store->GetCertIssuerSource());

  // Allow the path builder to discover the explicitly provided intermediates in
  // |input_cert|.
  CertIssuerSourceStatic intermediates;
  AddIntermediatesToIssuerSource(input_cert, &intermediates);
  path_builder.AddCertIssuerSource(&intermediates);

  // TODO(crbug.com/649017): Allow the path builder to discover intermediates
  // through AIA fetching.

  path_builder.Run();

  if (result.best_result_index >= result.paths.size()) {
    // TODO(crbug.com/634443): What errors to communicate? Maybe the path
    // builder should always return some partial path (even if just containing
    // the target), then there is a CertErrors to test.
    verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
    return;
  }

  // Use the best path that was built. This could be a partial path, or it could
  // be a valid complete path.
  const CertPathBuilder::ResultPath& partial_path =
      *result.paths[result.best_result_index].get();

  if (partial_path.path.trust_anchor) {
    verify_result->is_issued_by_known_root =
        trust_store->IsKnownRoot(partial_path.path.trust_anchor);

    verify_result->is_issued_by_additional_trust_anchor =
        trust_store->IsAdditionalTrustAnchor(partial_path.path.trust_anchor);
  } else {
    verify_result->cert_status |= CERT_STATUS_AUTHORITY_INVALID;
  }

  verify_result->verified_cert =
      CreateVerifiedCertChain(input_cert, partial_path);

  AppendPublicKeyHashes(partial_path, &verify_result->public_key_hashes);
  MapPathBuilderErrorsToCertStatus(partial_path, hostname,
                                   &verify_result->cert_status);
}

int CertVerifyProcBuiltin::VerifyInternal(
    X509Certificate* input_cert,
    const std::string& hostname,
    const std::string& ocsp_response,
    int flags,
    CRLSet* crl_set,
    const CertificateList& additional_trust_anchors,
    CertVerifyResult* verify_result) {
  DoVerify(input_cert, hostname, ocsp_response, flags, crl_set,
           additional_trust_anchors, verify_result);

  return IsCertStatusError(verify_result->cert_status)
             ? MapCertStatusToNetError(verify_result->cert_status)
             : OK;
}

}  // namespace

scoped_refptr<CertVerifyProc> CreateCertVerifyProcBuiltin() {
  return scoped_refptr<CertVerifyProc>(new CertVerifyProcBuiltin());
}

}  // namespace net
