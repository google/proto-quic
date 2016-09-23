// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_nss.h"

#include <cert.h>
#include <certdb.h>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/task_runner.h"
#include "crypto/nss_util.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"

// TODO(mattm): structure so that supporting ChromeOS multi-profile stuff is
// doable (Have a TrustStoreChromeOS which uses net::NSSProfileFilterChromeOS,
// similar to CertVerifyProcChromeOS.)

namespace net {

namespace {

// Get all certs in NSS which have a subject matching |der_name| and which are
// marked as a trusted CA.
void GetAnchors(const scoped_refptr<ParsedCertificate>& cert,
                SECTrustType trust_type,
                TrustAnchors* out_anchors) {
  crypto::EnsureNSSInit();

  SECItem name;
  // Use the original issuer value instead of the normalized version. NSS does a
  // less extensive normalization in its Name comparisons, so our normalized
  // version may not match the unnormalized version.
  name.len = cert->tbs().issuer_tlv.Length();
  name.data = const_cast<uint8_t*>(cert->tbs().issuer_tlv.UnsafeData());
  // |validOnly| in CERT_CreateSubjectCertList controls whether to return only
  // certs that are valid at |sorttime|. Expiration isn't meaningful for trust
  // anchors, so request all the matches.
  CERTCertList* found_certs = CERT_CreateSubjectCertList(
      nullptr /* certList */, CERT_GetDefaultCertDB(), &name,
      PR_Now() /* sorttime */, PR_FALSE /* validOnly */);
  if (!found_certs)
    return;

  for (CERTCertListNode* node = CERT_LIST_HEAD(found_certs);
       !CERT_LIST_END(node, found_certs); node = CERT_LIST_NEXT(node)) {
    CERTCertTrust trust;
    if (CERT_GetCertTrust(node->cert, &trust) != SECSuccess)
      continue;

    // TODO(mattm): handle explicit distrust (blacklisting)?
    const int ca_trust = CERTDB_TRUSTED_CA;
    if ((SEC_GET_TRUST_FLAGS(&trust, trust_type) & ca_trust) != ca_trust)
      continue;

    CertErrors errors;
    scoped_refptr<ParsedCertificate> anchor_cert = ParsedCertificate::Create(
        node->cert->derCert.data, node->cert->derCert.len, {}, &errors);
    if (!anchor_cert) {
      // TODO(crbug.com/634443): return errors better.
      LOG(ERROR) << "Error parsing issuer certificate:\n"
                 << errors.ToDebugString();
      continue;
    }

    out_anchors->push_back(TrustAnchor::CreateFromCertificateNoConstraints(
        std::move(anchor_cert)));
  }
  CERT_DestroyCertList(found_certs);
}

class GetAnchorsRequest : public TrustStore::Request {
 public:
  explicit GetAnchorsRequest(const TrustStore::TrustAnchorsCallback& callback);
  // Destruction of the Request cancels it. GetAnchors will still run, but the
  // callback will not be called since the WeakPtr will be invalidated.
  ~GetAnchorsRequest() override = default;

  void Start(const scoped_refptr<ParsedCertificate>& cert,
             SECTrustType trust_type,
             base::TaskRunner* task_runner);

 private:
  void HandleGetAnchors(std::unique_ptr<TrustAnchors> anchors);

  TrustStore::TrustAnchorsCallback callback_;
  base::WeakPtrFactory<GetAnchorsRequest> weak_ptr_factory_;
};

GetAnchorsRequest::GetAnchorsRequest(
    const TrustStore::TrustAnchorsCallback& callback)
    : callback_(callback), weak_ptr_factory_(this) {}

void GetAnchorsRequest::Start(const scoped_refptr<ParsedCertificate>& cert,
                              SECTrustType trust_type,
                              base::TaskRunner* task_runner) {
  auto anchors = base::MakeUnique<TrustAnchors>();

  auto* anchors_ptr = anchors.get();
  task_runner->PostTaskAndReply(
      FROM_HERE, base::Bind(&GetAnchors, cert, trust_type, anchors_ptr),
      base::Bind(&GetAnchorsRequest::HandleGetAnchors,
                 weak_ptr_factory_.GetWeakPtr(), base::Passed(&anchors)));
}

void GetAnchorsRequest::HandleGetAnchors(
    std::unique_ptr<TrustAnchors> anchors) {
  base::ResetAndReturn(&callback_).Run(std::move(*anchors));
  // |this| may be deleted here.
}

}  // namespace

TrustStoreNSS::TrustStoreNSS(SECTrustType trust_type,
                             scoped_refptr<base::TaskRunner> nss_task_runner)
    : trust_type_(trust_type), nss_task_runner_(std::move(nss_task_runner)) {}

TrustStoreNSS::~TrustStoreNSS() = default;

void TrustStoreNSS::FindTrustAnchorsForCert(
    const scoped_refptr<ParsedCertificate>& cert,
    const TrustAnchorsCallback& callback,
    TrustAnchors* synchronous_matches,
    std::unique_ptr<Request>* out_req) const {
  if (callback.is_null())
    return;

  auto req = base::MakeUnique<GetAnchorsRequest>(callback);
  req->Start(cert, trust_type_, nss_task_runner_.get());
  *out_req = std::move(req);
}

}  // namespace net
