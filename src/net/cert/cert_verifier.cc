// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verifier.h"

#include <algorithm>
#include <memory>

#include "base/memory/ptr_util.h"
#include "base/sha1.h"
#include "build/build_config.h"
#include "net/cert/cert_verify_proc.h"

#if defined(OS_NACL)
#include "base/logging.h"
#else
#include "net/cert/multi_threaded_cert_verifier.h"
#endif

namespace net {

CertVerifier::RequestParams::RequestParams(
    X509Certificate* certificate,
    const std::string& hostname,
    int flags,
    const std::string& ocsp_response,
    const CertificateList& additional_trust_anchors)
    : hostname_(hostname), flags_(flags) {
  // Rather than store all of the original data, create a fingerprint based
  // on the hash of the request data.
  SHA1HashValue ocsp_hash;
  base::SHA1HashBytes(
      reinterpret_cast<const unsigned char*>(ocsp_response.data()),
      ocsp_response.size(), ocsp_hash.data);

  request_data_.reserve(additional_trust_anchors.size() + 3);
  request_data_.push_back(ocsp_hash);
  request_data_.push_back(certificate->fingerprint());
  request_data_.push_back(certificate->ca_fingerprint());
  for (const auto& trust_anchor : additional_trust_anchors)
    request_data_.push_back(trust_anchor->fingerprint());
}

CertVerifier::RequestParams::RequestParams(const RequestParams& other) =
    default;
CertVerifier::RequestParams::~RequestParams() {}

bool CertVerifier::RequestParams::operator<(
    const CertVerifier::RequestParams& other) const {
  if (flags_ != other.flags_)
    return flags_ < other.flags_;
  if (hostname_ != other.hostname_)
    return hostname_ < other.hostname_;
  return std::lexicographical_compare(
      request_data_.begin(), request_data_.end(), other.request_data_.begin(),
      other.request_data_.end(), SHA1HashValueLessThan());
}

bool CertVerifier::SupportsOCSPStapling() {
  return false;
}

std::unique_ptr<CertVerifier> CertVerifier::CreateDefault() {
#if defined(OS_NACL)
  NOTIMPLEMENTED();
  return std::unique_ptr<CertVerifier>();
#else
  return base::WrapUnique(
      new MultiThreadedCertVerifier(CertVerifyProc::CreateDefault()));
#endif
}

}  // namespace net
