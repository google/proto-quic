// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_result.h"

#include "net/cert/x509_certificate.h"

namespace net {

CertVerifyResult::CertVerifyResult() {
  Reset();
}

CertVerifyResult::CertVerifyResult(const CertVerifyResult& other) = default;

CertVerifyResult::~CertVerifyResult() {
}

void CertVerifyResult::Reset() {
  verified_cert = NULL;
  cert_status = 0;
  has_md2 = false;
  has_md4 = false;
  has_md5 = false;
  has_sha1 = false;
  has_sha1_leaf = false;
  is_issued_by_known_root = false;
  is_issued_by_additional_trust_anchor = false;
  common_name_fallback_used = false;

  public_key_hashes.clear();
}

}  // namespace net
