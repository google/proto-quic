// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/do_nothing_ct_verifier.h"

#include "net/base/net_errors.h"

namespace net {

DoNothingCTVerifier::DoNothingCTVerifier() = default;
DoNothingCTVerifier::~DoNothingCTVerifier() = default;

int DoNothingCTVerifier::Verify(
    X509Certificate* cert,
    const std::string& stapled_ocsp_response,
    const std::string& sct_list_from_tls_extension,
    SignedCertificateTimestampAndStatusList* output_scts,
    const NetLogWithSource& net_log) {
  output_scts->clear();
  return ERR_CT_NO_SCTS_VERIFIED_OK;
}

}  // namespace net
