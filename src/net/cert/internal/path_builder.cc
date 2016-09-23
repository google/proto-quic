// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/path_builder.h"

#include <set>
#include <unordered_set>

#include "base/callback_helpers.h"
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

  // Gets the next candidate issuer. If an issuer is ready synchronously, SYNC
  // is returned and the cert is stored in |*cert|.  If an issuer is not
  // ready, ASYNC is returned and |callback| will be called once |*out_cert| has
  // been set. If |callback| is null, always completes synchronously.
  //
  // In either case, if all issuers have been exhausted, |*out| is cleared.
  CompletionStatus GetNextIssuer(CertificateOrTrustAnchor* out,
                                 const base::Closure& callback);

  // Returns the |cert| for which issuers are being retrieved.
  const ParsedCertificate* cert() const { return cert_.get(); }
  scoped_refptr<ParsedCertificate> reference_cert() const { return cert_; }

 private:
  void DoAsyncIssuerQuery();
  void GotAsyncAnchors(TrustAnchors anchors);
  void GotAsyncCerts(CertIssuerSource::Request* request);
  void NotifyIfNecessary();

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
  // If asynchronous requests were made, how many of them are still outstanding?
  size_t pending_async_results_;
  // Owns the Request objects for any asynchronous requests so that they will be
  // cancelled if CertIssuersIter is destroyed.
  std::vector<std::unique_ptr<CertIssuerSource::Request>>
      pending_async_requests_;
  std::unique_ptr<TrustStore::Request> pending_anchor_request_;

  // When GetNextIssuer was called and returned asynchronously, |*out_| is
  // where the result will be stored, and |callback_| will be run when the
  // result is ready.
  CertificateOrTrustAnchor* out_;
  base::Closure callback_;

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

CompletionStatus CertIssuersIter::GetNextIssuer(CertificateOrTrustAnchor* out,
                                                const base::Closure& callback) {
  // Should not be called again while already waiting for an async result.
  DCHECK(callback_.is_null());

  if (!did_initial_query_) {
    did_initial_query_ = true;
    trust_store_->FindTrustAnchorsForCert(
        cert_,
        callback.is_null() ? TrustStore::TrustAnchorsCallback()
                           : base::Bind(&CertIssuersIter::GotAsyncAnchors,
                                        base::Unretained(this)),
        &anchors_, &pending_anchor_request_);

    for (auto* cert_issuer_source : *cert_issuer_sources_) {
      ParsedCertificateList new_issuers;
      cert_issuer_source->SyncGetIssuersOf(cert(), &new_issuers);
      for (scoped_refptr<ParsedCertificate>& issuer : new_issuers) {
        if (present_issuers_.find(issuer->der_cert().AsStringPiece()) !=
            present_issuers_.end())
          continue;
        present_issuers_.insert(issuer->der_cert().AsStringPiece());
        issuers_.push_back(std::move(issuer));
      }
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
    return CompletionStatus::SYNC;
  }

  if (pending_anchor_request_) {
    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << ") Still waiting for async trust anchor results.";
    out_ = out;
    callback_ = callback;
    return CompletionStatus::ASYNC;
  }

  if (cur_issuer_ < issuers_.size()) {
    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << "): returning issuer " << cur_issuer_ << " of "
             << issuers_.size();
    // Still have issuers that haven't been returned yet, return one of them.
    // A reference to the returned issuer is retained, since |present_issuers_|
    // points to data owned by it.
    *out = CertificateOrTrustAnchor(issuers_[cur_issuer_++]);
    return CompletionStatus::SYNC;
  }

  if (did_async_issuer_query_) {
    if (pending_async_results_ == 0) {
      DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
               << ") Reached the end of all available issuers.";
      // Reached the end of all available issuers.
      *out = CertificateOrTrustAnchor();
      return CompletionStatus::SYNC;
    }

    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << ") Still waiting for async results from other "
                "CertIssuerSources.";
    // Still waiting for async results from other CertIssuerSources.
    out_ = out;
    callback_ = callback;
    return CompletionStatus::ASYNC;
  }
  // Reached the end of synchronously gathered issuers.

  if (callback.is_null()) {
    // Synchronous-only mode, don't try to query async sources.
    *out = CertificateOrTrustAnchor();
    return CompletionStatus::SYNC;
  }

  // Now issue request(s) for async ones (AIA, etc).
  DoAsyncIssuerQuery();

  if (pending_async_results_ == 0) {
    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << ") No cert sources have async results.";
    // No cert sources have async results.
    *out = CertificateOrTrustAnchor();
    return CompletionStatus::SYNC;
  }

  DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
           << ") issued AsyncGetIssuersOf call(s) (n=" << pending_async_results_
           << ")";
  out_ = out;
  callback_ = callback;
  return CompletionStatus::ASYNC;
}

void CertIssuersIter::DoAsyncIssuerQuery() {
  DCHECK(!did_async_issuer_query_);
  did_async_issuer_query_ = true;
  pending_async_results_ = 0;
  for (auto* cert_issuer_source : *cert_issuer_sources_) {
    std::unique_ptr<CertIssuerSource::Request> request;
    cert_issuer_source->AsyncGetIssuersOf(
        cert(),
        base::Bind(&CertIssuersIter::GotAsyncCerts, base::Unretained(this)),
        &request);
    if (request) {
      DVLOG(1) << "AsyncGetIssuersOf(" << CertDebugString(cert())
               << ") pending...";
      pending_async_results_++;
      pending_async_requests_.push_back(std::move(request));
    }
  }
}

void CertIssuersIter::GotAsyncAnchors(TrustAnchors anchors) {
  DVLOG(1) << "CertIssuersIter::GotAsyncAnchors(" << CertDebugString(cert())
           << "): " << anchors.size() << " anchors";
  for (scoped_refptr<TrustAnchor>& anchor : anchors)
    anchors_.push_back(std::move(anchor));
  pending_anchor_request_.reset();

  NotifyIfNecessary();
}

void CertIssuersIter::GotAsyncCerts(CertIssuerSource::Request* request) {
  DVLOG(1) << "CertIssuersIter::GotAsyncCerts(" << CertDebugString(cert())
           << ")";
  while (true) {
    scoped_refptr<ParsedCertificate> cert;
    CompletionStatus status = request->GetNext(&cert);
    if (!cert) {
      if (status == CompletionStatus::SYNC) {
        // Request is exhausted, no more results pending from that
        // CertIssuerSource.
        DCHECK_GT(pending_async_results_, 0U);
        pending_async_results_--;
      }
      break;
    }
    DCHECK_EQ(status, CompletionStatus::SYNC);
    if (present_issuers_.find(cert->der_cert().AsStringPiece()) !=
        present_issuers_.end())
      continue;
    present_issuers_.insert(cert->der_cert().AsStringPiece());
    issuers_.push_back(std::move(cert));
  }

  // TODO(mattm): re-sort remaining elements of issuers_ (remaining elements may
  // be more than the ones just inserted, depending on |cur_| value).

  NotifyIfNecessary();
}

void CertIssuersIter::NotifyIfNecessary() {
  // Notify that more results are available, if necessary.
  if (!callback_.is_null()) {
    if (cur_anchor_ < anchors_.size()) {
      DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
               << "): async returning anchor " << cur_anchor_ << " of "
               << anchors_.size();
      *out_ = CertificateOrTrustAnchor(std::move(anchors_[cur_anchor_++]));
      base::ResetAndReturn(&callback_).Run();
      return;
    }
    if (cur_issuer_ < issuers_.size()) {
      DCHECK(!pending_anchor_request_);
      DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
               << "): async returning issuer " << cur_issuer_ << " of "
               << issuers_.size();
      *out_ = CertificateOrTrustAnchor(std::move(issuers_[cur_issuer_++]));
      base::ResetAndReturn(&callback_).Run();
      return;
    }

    if (!did_async_issuer_query_)
      DoAsyncIssuerQuery();

    if (pending_async_results_ == 0) {
      DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
               << "): async returning empty result";
      *out_ = CertificateOrTrustAnchor();
      base::ResetAndReturn(&callback_).Run();
      return;
    }
    DVLOG(1) << "CertIssuersIter(" << CertDebugString(cert())
             << "): empty result, but other async results "
                "pending, waiting..";
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

  // Gets the next candidate path. If a path is ready synchronously, SYNC is
  // returned and the path is stored in |*path|.  If a path is not ready,
  // ASYNC is returned and |callback| will be called once |*path| has been set.
  // In either case, if all paths have been exhausted, |*path| is cleared.
  CompletionStatus GetNextPath(CertPath* path, const base::Closure& callback);

 private:
  enum State {
    STATE_NONE,
    STATE_GET_NEXT_ISSUER,
    STATE_GET_NEXT_ISSUER_COMPLETE,
    STATE_RETURN_A_PATH,
    STATE_BACKTRACK,
  };

  CompletionStatus DoLoop(bool allow_async);

  CompletionStatus DoGetNextIssuer(bool allow_async);
  CompletionStatus DoGetNextIssuerComplete();
  CompletionStatus DoBackTrack();

  void HandleGotNextIssuer(void);

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
  // The callback to be called if an async lookup generated a candidate path.
  base::Closure callback_;
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

CompletionStatus CertPathIter::GetNextPath(CertPath* path,
                                           const base::Closure& callback) {
  out_path_ = path;
  out_path_->Clear();
  CompletionStatus rv = DoLoop(!callback.is_null());
  if (rv == CompletionStatus::ASYNC) {
    callback_ = callback;
  } else {
    // Clear the reference to the output parameter as a precaution.
    out_path_ = nullptr;
  }
  return rv;
}

CompletionStatus CertPathIter::DoLoop(bool allow_async) {
  CompletionStatus result = CompletionStatus::SYNC;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_NONE:
        NOTREACHED();
        break;
      case STATE_GET_NEXT_ISSUER:
        result = DoGetNextIssuer(allow_async);
        break;
      case STATE_GET_NEXT_ISSUER_COMPLETE:
        result = DoGetNextIssuerComplete();
        break;
      case STATE_RETURN_A_PATH:
        // If the returned path did not verify, keep looking for other paths
        // (the trust root is not part of cur_path_, so don't need to
        // backtrack).
        next_state_ = STATE_GET_NEXT_ISSUER;
        result = CompletionStatus::SYNC;
        break;
      case STATE_BACKTRACK:
        result = DoBackTrack();
        break;
    }
  } while (result == CompletionStatus::SYNC && next_state_ != STATE_NONE &&
           next_state_ != STATE_RETURN_A_PATH);

  return result;
}

CompletionStatus CertPathIter::DoGetNextIssuer(bool allow_async) {
  next_state_ = STATE_GET_NEXT_ISSUER_COMPLETE;
  CompletionStatus rv = cur_path_.back()->GetNextIssuer(
      &next_issuer_, allow_async
                         ? base::Bind(&CertPathIter::HandleGotNextIssuer,
                                      base::Unretained(this))
                         : base::Closure());
  return rv;
}

CompletionStatus CertPathIter::DoGetNextIssuerComplete() {
  // If the issuer is a trust anchor signal readiness.
  if (next_issuer_.IsTrustAnchor()) {
    DVLOG(1) << "CertPathIter got anchor("
             << CertDebugString(next_issuer_.anchor->cert().get());
    next_state_ = STATE_RETURN_A_PATH;
    cur_path_.CopyPath(&out_path_->certs);
    out_path_->trust_anchor = std::move(next_issuer_.anchor);
    next_issuer_ = CertificateOrTrustAnchor();
    return CompletionStatus::SYNC;
  }

  if (next_issuer_.IsCertificate()) {
    // Skip this cert if it is already in the chain.
    if (cur_path_.IsPresent(next_issuer_.cert.get())) {
      next_state_ = STATE_GET_NEXT_ISSUER;
      return CompletionStatus::SYNC;
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
  return CompletionStatus::SYNC;
}

CompletionStatus CertPathIter::DoBackTrack() {
  DVLOG(1) << "CertPathIter backtracking...";
  cur_path_.Pop();
  if (cur_path_.Empty()) {
    // Exhausted all paths.
    next_state_ = STATE_NONE;
  } else {
    // Continue exploring issuers of the previous path.
    next_state_ = STATE_GET_NEXT_ISSUER;
  }
  return CompletionStatus::SYNC;
}

void CertPathIter::HandleGotNextIssuer(void) {
  DCHECK(!callback_.is_null());
  CompletionStatus rv = DoLoop(true /* allow_async */);
  if (rv == CompletionStatus::SYNC) {
    // Clear the reference to the output parameter as a precaution.
    out_path_ = nullptr;
    base::ResetAndReturn(&callback_).Run();
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

CompletionStatus CertPathBuilder::Run(const base::Closure& callback) {
  DCHECK_EQ(STATE_NONE, next_state_);
  next_state_ = STATE_GET_NEXT_PATH;
  CompletionStatus rv = DoLoop(!callback.is_null());

  if (rv == CompletionStatus::ASYNC)
    callback_ = callback;

  return rv;
}

CompletionStatus CertPathBuilder::DoLoop(bool allow_async) {
  CompletionStatus result = CompletionStatus::SYNC;

  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_NONE:
        NOTREACHED();
        break;
      case STATE_GET_NEXT_PATH:
        result = DoGetNextPath(allow_async);
        break;
      case STATE_GET_NEXT_PATH_COMPLETE:
        result = DoGetNextPathComplete();
        break;
    }
  } while (result == CompletionStatus::SYNC && next_state_ != STATE_NONE);

  return result;
}

CompletionStatus CertPathBuilder::DoGetNextPath(bool allow_async) {
  next_state_ = STATE_GET_NEXT_PATH_COMPLETE;
  CompletionStatus rv = cert_path_iter_->GetNextPath(
      &next_path_, allow_async ? base::Bind(&CertPathBuilder::HandleGotNextPath,
                                            base::Unretained(this))
                               : base::Closure());
  return rv;
}

void CertPathBuilder::HandleGotNextPath() {
  DCHECK(!callback_.is_null());
  CompletionStatus rv = DoLoop(true /* allow_async */);
  if (rv == CompletionStatus::SYNC)
    base::ResetAndReturn(&callback_).Run();
}

CompletionStatus CertPathBuilder::DoGetNextPathComplete() {
  if (next_path_.IsEmpty()) {
    // No more paths to check, signal completion.
    next_state_ = STATE_NONE;
    return CompletionStatus::SYNC;
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
    return CompletionStatus::SYNC;
  }

  // Path did not verify. Try more paths. If there are no more paths, the result
  // will be returned next time DoGetNextPathComplete is called with next_path_
  // empty.
  next_state_ = STATE_GET_NEXT_PATH;
  return CompletionStatus::SYNC;
}

void CertPathBuilder::AddResultPath(std::unique_ptr<ResultPath> result_path) {
  // TODO(mattm): set best_result_index based on number or severity of errors.
  if (result_path->valid)
    out_result_->best_result_index = out_result_->paths.size();
  // TODO(mattm): add flag to only return a single path or all attempted paths?
  out_result_->paths.push_back(std::move(result_path));
}

}  // namespace net
