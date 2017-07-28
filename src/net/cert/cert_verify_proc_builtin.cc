// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_builtin.h"

#include <string>
#include <vector>

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
#include "net/cert/internal/simple_path_builder_delegate.h"
#include "net/cert/internal/system_trust_store.h"
#include "net/cert/internal/verify_certificate_chain.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/der/encode_values.h"

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

// Appends the SHA256 hashes of |spki_bytes| to |*hashes|.
void AppendPublicKeyHashes(const der::Input& spki_bytes,
                           HashValueVector* hashes) {
  HashValue sha256(HASH_VALUE_SHA256);
  crypto::SHA256HashString(spki_bytes.AsStringPiece(), sha256.data(),
                           crypto::kSHA256Length);
  hashes->push_back(sha256);
}

// Appends the SubjectPublicKeyInfo hashes for all certificates in
// |partial_path| to |*hashes|.
void AppendPublicKeyHashes(const CertPathBuilder::ResultPath& partial_path,
                           HashValueVector* hashes) {
  for (const scoped_refptr<ParsedCertificate>& cert : partial_path.path.certs)
    AppendPublicKeyHashes(cert->tbs().spki_tlv, hashes);
}

// Sets the bits on |cert_status| for all the errors present in |errors| (the
// errors for a particular path).
void MapPathBuilderErrorsToCertStatus(const CertPathErrors& errors,
                                      CertStatus* cert_status) {
  // If there were no errors, nothing to do.
  if (!errors.ContainsHighSeverityErrors())
    return;

  if (errors.ContainsError(kRsaModulusTooSmall))
    *cert_status |= CERT_STATUS_WEAK_KEY;

  if (errors.ContainsError(kValidityFailedNotAfter) ||
      errors.ContainsError(kValidityFailedNotBefore)) {
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

  scoped_refptr<X509Certificate> result = X509Certificate::CreateFromHandle(
      target_cert->os_cert_handle(), intermediates);
  // |target_cert| was already successfully parsed, so this should never fail.
  DCHECK(result);

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
  CertErrors parsing_errors;

  // Parse the target certificate.
  scoped_refptr<ParsedCertificate> target = ParseCertificateFromOSHandle(
      input_cert->os_cert_handle(), &parsing_errors);
  if (!target) {
    // TODO(crbug.com/634443): Surface these parsing errors?
    verify_result->cert_status |= CERT_STATUS_INVALID;
    return;
  }

  std::unique_ptr<SystemTrustStore> ssl_trust_store =
      CreateSslSystemTrustStore();

  for (const auto& x509_cert : additional_trust_anchors) {
    scoped_refptr<ParsedCertificate> cert = ParseCertificateFromOSHandle(
        x509_cert->os_cert_handle(), &parsing_errors);
    if (cert)
      ssl_trust_store->AddTrustAnchor(cert);
    // TODO(eroman): Surface parsing errors of additional trust anchor.
  }

  // TODO(eroman): The path building code in this file enforces its idea of weak
  // keys, and separately cert_verify_proc.cc also checks the chains with its
  // own policy. These policies should be aligned, to give path building the
  // best chance of finding a good path.
  SimplePathBuilderDelegate path_builder_delegate(1024);

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
  CertPathBuilder path_builder(
      target, ssl_trust_store->GetTrustStore(), &path_builder_delegate,
      verification_time, KeyPurpose::SERVER_AUTH, InitialExplicitPolicy::kFalse,
      {AnyPolicy()} /* user_initial_policy_set*/,
      InitialPolicyMappingInhibit::kFalse, InitialAnyPolicyInhibit::kFalse,
      &result);

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

  const ParsedCertificate* trusted_cert = partial_path.path.GetTrustedCert();
  if (trusted_cert) {
    verify_result->is_issued_by_known_root =
        ssl_trust_store->IsKnownRoot(trusted_cert);

    verify_result->is_issued_by_additional_trust_anchor =
        ssl_trust_store->IsAdditionalTrustAnchor(trusted_cert);
  }

  verify_result->verified_cert =
      CreateVerifiedCertChain(input_cert, partial_path);

  AppendPublicKeyHashes(partial_path, &verify_result->public_key_hashes);
  MapPathBuilderErrorsToCertStatus(partial_path.errors,
                                   &verify_result->cert_status);

  // TODO(eroman): Is it possible that IsValid() fails but no errors were set in
  // partial_path.errors?
  CHECK(partial_path.IsValid() ||
        IsCertStatusError(verify_result->cert_status));

  if (partial_path.errors.ContainsHighSeverityErrors()) {
    LOG(ERROR) << "CertVerifyProcBuiltin for " << hostname << " failed:\n"
               << partial_path.errors.ToDebugString(partial_path.path.certs);
  }
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
