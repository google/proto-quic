// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/path_builder.h"

#include <set>
#include <unordered_set>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "net/base/net_errors.h"
#include "net/cert/internal/cert_issuer_source.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/parse_name.h"  // For CertDebugString.
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_certificate_chain.h"
#include "net/cert/internal/verify_name_match.h"
#include "net/der/parser.h"
#include "net/der/tag.h"

namespace net {

namespace {

using CertIssuerSources = std::vector<CertIssuerSource*>;

// TODO(mattm): decide how much debug logging to keep.
std::string CertDebugString(const ParsedCertificate* cert) {
  RDNSequence subject, issuer;
  std::string subject_str, issuer_str;
  if (!ParseName(cert->tbs().subject_tlv, &subject) ||
      !ConvertToRFC2253(subject, &subject_str))
    subject_str = "???";
  if (!ParseName(cert->tbs().issuer_tlv, &issuer) ||
      !ConvertToRFC2253(issuer, &issuer_str))
    issuer_str = "???";

  return subject_str + "(" + issuer_str + ")";
}

// This structure contains either a ParsedCertificate or a TrustAnchor. It is
// used to describe the result of getting a certificate's issuer, which may
// either be another certificate, or a trust anchor.
struct CertificateOrTrustAnchor {
  CertificateOrTrustAnchor() {}

  explicit CertificateOrTrustAnchor(scoped_refptr<ParsedCertificate> cert)
      : cert(std::move(cert)) {}

  explicit CertificateOrTrustAnchor(scoped_refptr<TrustAnchor> anchor)
      : anchor(std::move(anchor)) {}

  bool IsTrustAnchor() const { return anchor.get() != nullptr; }
  bool IsCertificate() const { return cert.get() != nullptr; }
  bool IsEmpty() const { return !IsTrustAnchor() && !IsCertificate(); }

  scoped_refptr<ParsedCertificate> cert;
  scoped_refptr<TrustAnchor> anchor;
};

// CertIssuersIter iterates through the intermediates from |cert_issuer_sources|
// which may be issuers of |cert|.
class CertIssuersIter {
 public:
  // Constructs the CertIssuersIter. |*cert_issuer_sources| and |*trust_store|
  // must be valid for the lifetime of the CertIssuersIter.
  CertIssuersIter(scoped_refptr<ParsedCertificate> cert,
                  CertIssuerSources* cert_issuer_sources,
                  const TrustStore* trust_store);

  // Gets the next candidate issuer, or clears |*out| when all issuers have been
  // exhausted.
  void GetNextIssuer(CertificateOrTrustAnchor* out);

  // Returns the |cert| for which issuers are being retrieved.
  const ParsedCertificate* cert() const { return cert_.get(); }
  scoped_refptr<ParsedCertificate> reference_cert() const { return cert_; }

 private:
  void AddIssuers(ParsedCertificateList issuers);
  void DoAsyncIssuerQuery();

  scoped_refptr<ParsedCertificate> cert_;
  CertIssuerSources* cert_issuer_sources_;
  const TrustStore* trust_store_;

  // The list of trust anchors that match the issuer name for |cert_|.
  TrustAnchors anchors_;
  // The index of the next trust anchor in |anchors_| to return.
  size_t cur_anchor_ = 0;

  // The list of issuers for |cert_|. This is added to incrementally (first
  // synchronous results, then possibly multiple times as asynchronous results
  // arrive.) The issuers may be re-sorted each time new issuers are added, but
  // only the results from |cur_| onwards should be sorted, since the earlier
  // results were already returned.
  // Elements should not be removed from |issuers_| once added, since
  // |present_issuers_| will point to data owned by the certs.
  ParsedCertificateList issuers_;
  // The index of the next cert in |issuers_| to return.
  size_t cur_issuer_ = 0;

  // Set of DER-encoded values for the certs in |issuers_|. Used to prevent
  // duplicates. This is based on the full DER of the cert to allow different
  // versions of the same certificate to be tried in different candidate paths.
  // This points to data owned by |issuers_|.
  std::unordered_set<base::StringPiece, base::StringPieceHash> present_issuers_;

  // Tracks which requests have been made yet.
  bool did_initial_query_ = false;
  bool did_async_issuer_query_ = false;
  // Index into pending_async_requests_ that is the next one to process.
  size_t cur_async_request_ = 0;
  // Owns the Request objects for any asynchronous requests so that they will be
  // cancelled if CertIssuersIter is destroyed.
  std::vector<std::unique_ptr<CertIssuerSource::Request>>
      pending_async_requests_;

  DISALLOW_COPY_AND_ASSIGN(CertIssuersIter);
};

CertIssuersIter::CertIssuersIter(scoped_refptr<ParsedCertificate> in_cert,
                                 CertIssuerSources* cert_issuer_sources,
                                 const TrustStore* trust_store)
    : cert_(in_cert),
      cert_issuer_sources_(cert_issuer_sources),
      trust_store_(trust_store) {
  DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert()) << ") created";
}

void CertIssuersIter::GetNextIssuer(CertificateOrTrustAnchor* out) {
  if (!did_initial_query_) {
    did_initial_query_ = true;
    trust_store_->FindTrustAnchorsForCert(cert_, &anchors_);

    for (auto* cert_issuer_source : *cert_issuer_sources_) {
      ParsedCertificateList new_issuers;
      cert_issuer_source->SyncGetIssuersOf(cert(), &new_issuers);
      AddIssuers(std::move(new_issuers));
    }
    DVLOG(1) << anchors_.size() << " sync anchors, " << issuers_.size()
             << " sync issuers";
    // TODO(mattm): sort by notbefore, etc (eg if cert issuer matches a trust
    // anchor subject (or is a trust anchor), that should be sorted higher too.
    // See big list of possible sorting hints in RFC 4158.)
    // (Update PathBuilderKeyRolloverTest.TestRolloverBothRootsTrusted once that
    // is done)
  }

  // Return possible trust anchors first.
  if (cur_anchor_ < anchors_.size()) {
    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << "): returning anchor " << cur_anchor_ << " of "
             << anchors_.size();
    // Still have anchors that haven't been returned yet, return one of them.
    *out = CertificateOrTrustAnchor(anchors_[cur_anchor_++]);
    return;
  }

  // If there aren't any issuers left, block until async results are ready.
  if (cur_issuer_ >= issuers_.size()) {
    if (!did_async_issuer_query_) {
      // Now issue request(s) for async ones (AIA, etc).
      DoAsyncIssuerQuery();
    }

    // TODO(eroman): Rather than blocking on the async requests in FIFO order,
    // consume in the order they become ready.
    while (cur_async_request_ < pending_async_requests_.size()) {
      ParsedCertificateList new_issuers;
      pending_async_requests_[cur_async_request_]->GetNext(&new_issuers);
      if (new_issuers.empty()) {
        // Request is exhausted, no more results pending from that
        // CertIssuerSource.
        pending_async_requests_[cur_async_request_++].reset();
        continue;
      }

      AddIssuers(std::move(new_issuers));
      break;
    }
  }

  if (cur_issuer_ < issuers_.size()) {
    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << "): returning issuer " << cur_issuer_ << " of "
             << issuers_.size();
    // Still have issuers that haven't been returned yet, return one of them.
    // A reference to the returned issuer is retained, since |present_issuers_|
    // points to data owned by it.
    *out = CertificateOrTrustAnchor(issuers_[cur_issuer_++]);
    return;
  }

  DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
           << ") Reached the end of all available issuers.";
  // Reached the end of all available issuers.
  *out = CertificateOrTrustAnchor();
}

void CertIssuersIter::AddIssuers(ParsedCertificateList new_issuers) {
  for (scoped_refptr<ParsedCertificate>& issuer : new_issuers) {
    if (present_issuers_.find(issuer->der_cert().AsStringPiece()) !=
        present_issuers_.end())
      continue;
    present_issuers_.insert(issuer->der_cert().AsStringPiece());
    issuers_.push_back(std::move(issuer));
  }
}

void CertIssuersIter::DoAsyncIssuerQuery() {
  DCHECK(!did_async_issuer_query_);
  did_async_issuer_query_ = true;
  cur_async_request_ = 0;
  for (auto* cert_issuer_source : *cert_issuer_sources_) {
    std::unique_ptr<CertIssuerSource::Request> request;
    cert_issuer_source->AsyncGetIssuersOf(cert(), &request);
    if (request) {
      DVLOG(1) << "AsyncGetIssuersOf(" << CertDebugString(cert())
               << ") pending...";
      pending_async_requests_.push_back(std::move(request));
    }
  }
}

// CertIssuerIterPath tracks which certs are present in the path and prevents
// paths from being built which repeat any certs (including different versions
// of the same cert, based on Subject+SubjectAltName+SPKI).
class CertIssuerIterPath {
 public:
  // Returns true if |cert| is already present in the path.
  bool IsPresent(const ParsedCertificate* cert) const {
    return present_certs_.find(GetKey(cert)) != present_certs_.end();
  }

  // Appends |cert_issuers_iter| to the path. The cert referred to by
  // |cert_issuers_iter| must not be present in the path already.
  void Append(std::unique_ptr<CertIssuersIter> cert_issuers_iter) {
    bool added =
        present_certs_.insert(GetKey(cert_issuers_iter->cert())).second;
    DCHECK(added);
    cur_path_.push_back(std::move(cert_issuers_iter));
  }

  // Pops the last CertIssuersIter off the path.
  void Pop() {
    size_t num_erased = present_certs_.erase(GetKey(cur_path_.back()->cert()));
    DCHECK_EQ(num_erased, 1U);
    cur_path_.pop_back();
  }

  // Copies the ParsedCertificate elements of the current path to |*out_path|.
  void CopyPath(ParsedCertificateList* out_path) {
    out_path->clear();
    for (const auto& node : cur_path_)
      out_path->push_back(node->reference_cert());
  }

  // Returns true if the path is empty.
  bool Empty() const { return cur_path_.empty(); }

  // Returns the last CertIssuersIter in the path.
  CertIssuersIter* back() { return cur_path_.back().get(); }

  std::string PathDebugString() {
    std::string s;
    for (const auto& node : cur_path_) {
      if (!s.empty())
        s += " <- ";
      s += CertDebugString(node->cert());
    }
    return s;
  }

 private:
  using Key =
      std::tuple<base::StringPiece, base::StringPiece, base::StringPiece>;

  static Key GetKey(const ParsedCertificate* cert) {
    // TODO(mattm): ideally this would use a normalized version of
    // SubjectAltName, but it's not that important just for LoopChecker.
    //
    // Note that subject_alt_names_extension().value will be empty if the cert
    // had no SubjectAltName extension, so there is no need for a condition on
    // has_subject_alt_names().
    return Key(cert->normalized_subject().AsStringPiece(),
               cert->subject_alt_names_extension().value.AsStringPiece(),
               cert->tbs().spki_tlv.AsStringPiece());
  }

  std::vector<std::unique_ptr<CertIssuersIter>> cur_path_;

  // This refers to data owned by |cur_path_|.
  // TODO(mattm): use unordered_set. Requires making a hash function for Key.
  std::set<Key> present_certs_;
};

}  // namespace

CertPath::CertPath() = default;
CertPath::~CertPath() = default;

void CertPath::Clear() {
  trust_anchor = nullptr;
  certs.clear();
}

bool CertPath::IsEmpty() const {
  return certs.empty();
}

// CertPathIter generates possible paths from |cert| to a trust anchor in
// |trust_store|, using intermediates from the |cert_issuer_source| objects if
// necessary.
class CertPathIter {
 public:
  CertPathIter(scoped_refptr<ParsedCertificate> cert,
               const TrustStore* trust_store);

  // Adds a CertIssuerSource to provide intermediates for use in path building.
  // The |*cert_issuer_source| must remain valid for the lifetime of the
  // CertPathIter.
  void AddCertIssuerSource(CertIssuerSource* cert_issuer_source);

  // Gets the next candidate path, or clears |*path| when all paths have been
  // exhausted.
  void GetNextPath(CertPath* path);

 private:
  enum State {
    STATE_NONE,
    STATE_GET_NEXT_ISSUER,
    STATE_GET_NEXT_ISSUER_COMPLETE,
    STATE_RETURN_A_PATH,
    STATE_BACKTRACK,
  };

  void DoGetNextIssuer();
  void DoGetNextIssuerComplete();
  void DoBackTrack();

  // Stores the next candidate issuer, until it is used during the
  // STATE_GET_NEXT_ISSUER_COMPLETE step.
  CertificateOrTrustAnchor next_issuer_;
  // The current path being explored, made up of CertIssuerIters. Each node
  // keeps track of the state of searching for issuers of that cert, so that
  // when backtracking it can resume the search where it left off.
  CertIssuerIterPath cur_path_;
  // The CertIssuerSources for retrieving candidate issuers.
  CertIssuerSources cert_issuer_sources_;
  // The TrustStore for checking if a path ends in a trust anchor.
  const TrustStore* trust_store_;
  // The output variable for storing the next candidate path, which the client
  // passes in to GetNextPath. Only used for a single path output.
  CertPath* out_path_;
  // Current state of the state machine.
  State next_state_;

  DISALLOW_COPY_AND_ASSIGN(CertPathIter);
};

CertPathIter::CertPathIter(scoped_refptr<ParsedCertificate> cert,
                           const TrustStore* trust_store)
    : next_issuer_(std::move(cert)),
      trust_store_(trust_store),
      next_state_(STATE_GET_NEXT_ISSUER_COMPLETE) {}

void CertPathIter::AddCertIssuerSource(CertIssuerSource* cert_issuer_source) {
  cert_issuer_sources_.push_back(cert_issuer_source);
}

// TODO(eroman): Simplify (doesn't need to use the "DoLoop" pattern).
void CertPathIter::GetNextPath(CertPath* path) {
  out_path_ = path;
  out_path_->Clear();
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_NONE:
        NOTREACHED();
        break;
      case STATE_GET_NEXT_ISSUER:
        DoGetNextIssuer();
        break;
      case STATE_GET_NEXT_ISSUER_COMPLETE:
        DoGetNextIssuerComplete();
        break;
      case STATE_RETURN_A_PATH:
        // If the returned path did not verify, keep looking for other paths
        // (the trust root is not part of cur_path_, so don't need to
        // backtrack).
        next_state_ = STATE_GET_NEXT_ISSUER;
        break;
      case STATE_BACKTRACK:
        DoBackTrack();
        break;
    }
  } while (next_state_ != STATE_NONE && next_state_ != STATE_RETURN_A_PATH);

  out_path_ = nullptr;
}

void CertPathIter::DoGetNextIssuer() {
  next_state_ = STATE_GET_NEXT_ISSUER_COMPLETE;
  cur_path_.back()->GetNextIssuer(&next_issuer_);
}

void CertPathIter::DoGetNextIssuerComplete() {
  // If the issuer is a trust anchor signal readiness.
  if (next_issuer_.IsTrustAnchor()) {
    DVLOG(1) << "CertPathIter got anchor("
             << CertDebugString(next_issuer_.anchor->cert().get());
    next_state_ = STATE_RETURN_A_PATH;
    cur_path_.CopyPath(&out_path_->certs);
    out_path_->trust_anchor = std::move(next_issuer_.anchor);
    next_issuer_ = CertificateOrTrustAnchor();
    return;
  }

  if (next_issuer_.IsCertificate()) {
    // Skip this cert if it is already in the chain.
    if (cur_path_.IsPresent(next_issuer_.cert.get())) {
      next_state_ = STATE_GET_NEXT_ISSUER;
      return;
    }

    cur_path_.Append(base::MakeUnique<CertIssuersIter>(
        std::move(next_issuer_.cert), &cert_issuer_sources_, trust_store_));
    next_issuer_ = CertificateOrTrustAnchor();
    DVLOG(1) << "CertPathIter cur_path_ = " << cur_path_.PathDebugString();
    // Continue descending the tree.
    next_state_ = STATE_GET_NEXT_ISSUER;
  } else {
    // TODO(mattm): should also include such paths in CertPathBuilder::Result,
    // maybe with a flag to enable it. Or use a visitor pattern so the caller
    // can decide what to do with any failed paths.
    // No more issuers for current chain, go back up and see if there are any
    // more for the previous cert.
    next_state_ = STATE_BACKTRACK;
  }
}

void CertPathIter::DoBackTrack() {
  DVLOG(1) << "CertPathIter backtracking...";
  cur_path_.Pop();
  if (cur_path_.Empty()) {
    // Exhausted all paths.
    next_state_ = STATE_NONE;
  } else {
    // Continue exploring issuers of the previous path.
    next_state_ = STATE_GET_NEXT_ISSUER;
  }
}

CertPathBuilder::ResultPath::ResultPath() = default;
CertPathBuilder::ResultPath::~ResultPath() = default;
CertPathBuilder::Result::Result() = default;
CertPathBuilder::Result::~Result() = default;

const CertPathBuilder::ResultPath* CertPathBuilder::Result::GetBestValidPath()
    const {
  DCHECK((paths.empty() && best_result_index == 0) ||
         best_result_index < paths.size());

  if (best_result_index >= paths.size())
    return nullptr;

  const ResultPath* result_path = paths[best_result_index].get();
  if (result_path->valid)
    return result_path;

  return nullptr;
}

bool CertPathBuilder::Result::HasValidPath() const {
  return GetBestValidPath() != nullptr;
}

CertPathBuilder::CertPathBuilder(scoped_refptr<ParsedCertificate> cert,
                                 const TrustStore* trust_store,
                                 const SignaturePolicy* signature_policy,
                                 const der::GeneralizedTime& time,
                                 Result* result)
    : cert_path_iter_(new CertPathIter(std::move(cert), trust_store)),
      signature_policy_(signature_policy),
      time_(time),
      next_state_(STATE_NONE),
      out_result_(result) {}

CertPathBuilder::~CertPathBuilder() {}

void CertPathBuilder::AddCertIssuerSource(
    CertIssuerSource* cert_issuer_source) {
  cert_path_iter_->AddCertIssuerSource(cert_issuer_source);
}

// TODO(eroman): Simplify (doesn't need to use the "DoLoop" pattern).
void CertPathBuilder::Run() {
  DCHECK_EQ(STATE_NONE, next_state_);
  next_state_ = STATE_GET_NEXT_PATH;

  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_NONE:
        NOTREACHED();
        break;
      case STATE_GET_NEXT_PATH:
        DoGetNextPath();
        break;
      case STATE_GET_NEXT_PATH_COMPLETE:
        DoGetNextPathComplete();
        break;
    }
  } while (next_state_ != STATE_NONE);
}

void CertPathBuilder::DoGetNextPath() {
  next_state_ = STATE_GET_NEXT_PATH_COMPLETE;
  cert_path_iter_->GetNextPath(&next_path_);
}

void CertPathBuilder::DoGetNextPathComplete() {
  if (next_path_.IsEmpty()) {
    // No more paths to check, signal completion.
    next_state_ = STATE_NONE;
    return;
  }

  // Verify the entire certificate chain.
  auto result_path = base::MakeUnique<ResultPath>();
  bool verify_result =
      VerifyCertificateChain(next_path_.certs, next_path_.trust_anchor.get(),
                             signature_policy_, time_, &result_path->errors);
  DVLOG(1) << "CertPathBuilder VerifyCertificateChain result = "
           << result_path->valid;
  result_path->path = next_path_;
  result_path->valid = verify_result;
  AddResultPath(std::move(result_path));

  if (verify_result) {
    // Found a valid path, return immediately.
    // TODO(mattm): add debug/test mode that tries all possible paths.
    next_state_ = STATE_NONE;
    return;
  }

  // Path did not verify. Try more paths. If there are no more paths, the result
  // will be returned next time DoGetNextPathComplete is called with next_path_
  // empty.
  next_state_ = STATE_GET_NEXT_PATH;
}

void CertPathBuilder::AddResultPath(std::unique_ptr<ResultPath> result_path) {
  // TODO(mattm): set best_result_index based on number or severity of errors.
  if (result_path->valid)
    out_result_->best_result_index = out_result_->paths.size();
  // TODO(mattm): add flag to only return a single path or all attempted paths?
  out_result_->paths.push_back(std::move(result_path));
}

}  // namespace net
