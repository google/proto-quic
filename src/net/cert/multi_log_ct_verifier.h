// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_MULTI_LOG_CT_VERIFIER_H_
#define NET_CERT_MULTI_LOG_CT_VERIFIER_H_

#include <map>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/signed_certificate_timestamp.h"

namespace net {

namespace ct {
struct LogEntry;
}  // namespace ct

class CTLogVerifier;

// A Certificate Transparency verifier that can verify Signed Certificate
// Timestamps from multiple logs.
// It must be initialized with a list of logs by calling AddLogs.
class NET_EXPORT MultiLogCTVerifier : public CTVerifier {
 public:
  MultiLogCTVerifier();
  ~MultiLogCTVerifier() override;

  void AddLogs(
      const std::vector<scoped_refptr<const CTLogVerifier>>& log_verifiers);

  // CTVerifier implementation:
  int Verify(X509Certificate* cert,
             const std::string& stapled_ocsp_response,
             const std::string& sct_list_from_tls_extension,
             ct::CTVerifyResult* result,
             const BoundNetLog& net_log) override;

  void SetObserver(Observer* observer) override;

 private:
  // Verify a list of SCTs from |encoded_sct_list| over |expected_entry|,
  // placing the verification results in |result|. The SCTs in the list
  // come from |origin| (as will be indicated in the origin field of each SCT).
  bool VerifySCTs(const std::string& encoded_sct_list,
                  const ct::LogEntry& expected_entry,
                  ct::SignedCertificateTimestamp::Origin origin,
                  X509Certificate* cert,
                  ct::CTVerifyResult* result);

  // Verifies a single, parsed SCT against all logs.
  bool VerifySingleSCT(scoped_refptr<ct::SignedCertificateTimestamp> sct,
                       const ct::LogEntry& expected_entry,
                       X509Certificate* cert,
                       ct::CTVerifyResult* result);

  // Mapping from a log's ID to the verifier for this log.
  // A log's ID is the SHA-256 of the log's key, as defined in section 3.2.
  // of RFC6962.
  std::map<std::string, scoped_refptr<const CTLogVerifier>> logs_;

  Observer* observer_;

  DISALLOW_COPY_AND_ASSIGN(MultiLogCTVerifier);
};

}  // namespace net

#endif  // NET_CERT_MULTI_LOG_CT_VERIFIER_H_
