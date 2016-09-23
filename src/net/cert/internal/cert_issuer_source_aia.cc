// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_issuer_source_aia.h"

#include "base/bind.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/internal/cert_errors.h"
#include "url/gurl.h"

namespace net {

namespace {

// TODO(mattm): These are arbitrary choices. Re-evaluate.
const int kTimeoutMilliseconds = 10000;
const int kMaxResponseBytes = 65536;
const int kMaxFetchesPerCert = 5;

class AiaRequest : public CertIssuerSource::Request {
 public:
  explicit AiaRequest(const CertIssuerSource::IssuerCallback& issuers_callback);
  ~AiaRequest() override;

  // CertIssuerSource::Request implementation.
  CompletionStatus GetNext(scoped_refptr<ParsedCertificate>* out_cert) override;

  void AddCertFetcherRequest(
      std::unique_ptr<CertNetFetcher::Request> cert_fetcher_request);

  void OnFetchCompleted(Error error, const std::vector<uint8_t>& fetched_bytes);

 private:
  bool HasNext() const { return current_result_ < results_.size(); }

  CertIssuerSource::IssuerCallback issuers_callback_;
  std::vector<std::unique_ptr<CertNetFetcher::Request>> cert_fetcher_requests_;
  size_t pending_requests_ = 0;
  ParsedCertificateList results_;
  size_t current_result_ = 0;

  DISALLOW_COPY_AND_ASSIGN(AiaRequest);
};

AiaRequest::AiaRequest(const CertIssuerSource::IssuerCallback& issuers_callback)
    : issuers_callback_(issuers_callback) {}

AiaRequest::~AiaRequest() = default;

CompletionStatus AiaRequest::GetNext(
    scoped_refptr<ParsedCertificate>* out_cert) {
  if (HasNext()) {
    *out_cert = std::move(results_[current_result_++]);
    return CompletionStatus::SYNC;
  }
  *out_cert = nullptr;
  if (pending_requests_)
    return CompletionStatus::ASYNC;
  return CompletionStatus::SYNC;
}

void AiaRequest::AddCertFetcherRequest(
    std::unique_ptr<CertNetFetcher::Request> cert_fetcher_request) {
  DCHECK(cert_fetcher_request);
  cert_fetcher_requests_.push_back(std::move(cert_fetcher_request));
  pending_requests_++;
}

void AiaRequest::OnFetchCompleted(Error error,
                                  const std::vector<uint8_t>& fetched_bytes) {
  DCHECK_GT(pending_requests_, 0U);
  pending_requests_--;
  bool client_waiting_for_callback = !HasNext();
  if (error != OK) {
    // TODO(mattm): propagate error info.
    LOG(ERROR) << "AiaRequest::OnFetchCompleted got error " << error;
  } else {
    // RFC 5280 section 4.2.2.1:
    //
    //    Conforming applications that support HTTP or FTP for accessing
    //    certificates MUST be able to accept individual DER encoded
    //    certificates and SHOULD be able to accept "certs-only" CMS messages.
    //
    // TODO(mattm): Is supporting CMS message format important?
    //
    // TODO(mattm): Avoid copying bytes. Change the CertNetFetcher and
    // ParsedCertificate interface to allow passing through ownership of the
    // bytes.
    CertErrors errors;
    if (!ParsedCertificate::CreateAndAddToVector(fetched_bytes.data(),
                                                 fetched_bytes.size(), {},
                                                 &results_, &errors)) {
      // TODO(crbug.com/634443): propagate error info.
      LOG(ERROR) << "Error parsing cert retrieved from AIA:\n"
                 << errors.ToDebugString();
    }
  }
  // If the client is waiting for results, need to run callback if:
  //  * Some are available now.
  //  * The last fetch finished, even with no results. (Client needs to know to
  //    stop waiting.)
  if (client_waiting_for_callback && (HasNext() || pending_requests_ == 0))
    issuers_callback_.Run(this);
}

}  // namespace

CertIssuerSourceAia::CertIssuerSourceAia(CertNetFetcher* cert_fetcher)
    : cert_fetcher_(cert_fetcher) {}

CertIssuerSourceAia::~CertIssuerSourceAia() = default;

void CertIssuerSourceAia::SyncGetIssuersOf(const ParsedCertificate* cert,
                                           ParsedCertificateList* issuers) {
  // CertIssuerSourceAia never returns synchronous results.
}

void CertIssuerSourceAia::AsyncGetIssuersOf(
    const ParsedCertificate* cert,
    const IssuerCallback& issuers_callback,
    std::unique_ptr<Request>* out_req) {
  out_req->reset();

  if (!cert->has_authority_info_access())
    return;

  // RFC 5280 section 4.2.2.1:
  //
  //    An authorityInfoAccess extension may include multiple instances of
  //    the id-ad-caIssuers accessMethod.  The different instances may
  //    specify different methods for accessing the same information or may
  //    point to different information.

  std::vector<GURL> urls;
  for (const auto& uri : cert->ca_issuers_uris()) {
    GURL url(uri);
    if (url.is_valid()) {
      // TODO(mattm): do the kMaxFetchesPerCert check only on the number of
      // supported URL schemes, not all the URLs.
      if (urls.size() < kMaxFetchesPerCert) {
        urls.push_back(url);
      } else {
        // TODO(mattm): propagate error info.
        LOG(ERROR) << "kMaxFetchesPerCert exceeded, skipping";
      }
    } else {
      // TODO(mattm): propagate error info.
      LOG(ERROR) << "invalid AIA URL: " << uri;
    }
  }
  if (urls.empty())
    return;

  std::unique_ptr<AiaRequest> aia_request(new AiaRequest(issuers_callback));

  for (const auto& url : urls) {
    // TODO(mattm): add synchronous failure mode to FetchCaIssuers interface so
    // that this doesn't need to wait for async callback just to tell that an
    // URL has an unsupported scheme?
    aia_request->AddCertFetcherRequest(cert_fetcher_->FetchCaIssuers(
        url, kTimeoutMilliseconds, kMaxResponseBytes,
        base::Bind(&AiaRequest::OnFetchCompleted,
                   base::Unretained(aia_request.get()))));
  }

  *out_req = std::move(aia_request);
}

}  // namespace net
