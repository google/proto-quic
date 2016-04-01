// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/multi_log_ct_verifier.h"

#include <vector>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_objects_extractor.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/ct_signed_certificate_timestamp_log_param.h"
#include "net/cert/ct_verify_result.h"
#include "net/cert/sct_status_flags.h"
#include "net/cert/x509_certificate.h"
#include "net/log/net_log.h"

namespace net {

namespace {

// Record SCT verification status. This metric would help detecting presence
// of unknown CT logs as well as bad deployments (invalid SCTs).
void LogSCTStatusToUMA(ct::SCTVerifyStatus status) {
  UMA_HISTOGRAM_ENUMERATION(
      "Net.CertificateTransparency.SCTStatus", status, ct::SCT_STATUS_MAX);
}

// Record SCT origin enum. This metric measure the popularity
// of the various channels of providing SCTs for a certificate.
void LogSCTOriginToUMA(ct::SignedCertificateTimestamp::Origin origin) {
  UMA_HISTOGRAM_ENUMERATION("Net.CertificateTransparency.SCTOrigin",
                            origin,
                            ct::SignedCertificateTimestamp::SCT_ORIGIN_MAX);
}

// Count the number of SCTs that were available for each SSL connection
// (including SCTs embedded in the certificate).
// This metric would allow measuring:
// * Of all SSL connections, how many had SCTs available for validation.
// * When SCTs are available, how many are available per connection.
void LogNumSCTsToUMA(const ct::CTVerifyResult& result) {
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.CertificateTransparency.SCTsPerConnection",
                              result.invalid_scts.size() +
                                  result.verified_scts.size() +
                                  result.unknown_logs_scts.size(),
                              1,
                              10,
                              11);
}

}  // namespace

MultiLogCTVerifier::MultiLogCTVerifier() : observer_(nullptr) {
}

MultiLogCTVerifier::~MultiLogCTVerifier() { }

void MultiLogCTVerifier::AddLogs(
    const std::vector<scoped_refptr<const CTLogVerifier>>& log_verifiers) {
  for (const auto& log_verifier : log_verifiers) {
    VLOG(1) << "Adding CT log: " << log_verifier->description();
    logs_[log_verifier->key_id()] = log_verifier;
  }
}

void MultiLogCTVerifier::SetObserver(Observer* observer) {
  observer_ = observer;
}

int MultiLogCTVerifier::Verify(
    X509Certificate* cert,
    const std::string& stapled_ocsp_response,
    const std::string& sct_list_from_tls_extension,
    ct::CTVerifyResult* result,
    const BoundNetLog& net_log)  {
  DCHECK(cert);
  DCHECK(result);

  result->verified_scts.clear();
  result->invalid_scts.clear();
  result->unknown_logs_scts.clear();

  bool has_verified_scts = false;

  std::string embedded_scts;
  if (!cert->GetIntermediateCertificates().empty() &&
      ct::ExtractEmbeddedSCTList(
          cert->os_cert_handle(),
          &embedded_scts)) {
    ct::LogEntry precert_entry;

    has_verified_scts =
        ct::GetPrecertLogEntry(cert->os_cert_handle(),
                               cert->GetIntermediateCertificates().front(),
                               &precert_entry) &&
        VerifySCTs(embedded_scts, precert_entry,
                   ct::SignedCertificateTimestamp::SCT_EMBEDDED, cert, result);
  }

  std::string sct_list_from_ocsp;
  if (!stapled_ocsp_response.empty() &&
      !cert->GetIntermediateCertificates().empty()) {
    ct::ExtractSCTListFromOCSPResponse(
        cert->GetIntermediateCertificates().front(), cert->serial_number(),
        stapled_ocsp_response, &sct_list_from_ocsp);
  }

  // Log to Net Log, after extracting SCTs but before possibly failing on
  // X.509 entry creation.
  NetLog::ParametersCallback net_log_callback =
      base::Bind(&NetLogRawSignedCertificateTimestampCallback,
          &embedded_scts, &sct_list_from_ocsp, &sct_list_from_tls_extension);

  net_log.AddEvent(
      NetLog::TYPE_SIGNED_CERTIFICATE_TIMESTAMPS_RECEIVED,
      net_log_callback);

  ct::LogEntry x509_entry;
  if (ct::GetX509LogEntry(cert->os_cert_handle(), &x509_entry)) {
    has_verified_scts |= VerifySCTs(
        sct_list_from_ocsp, x509_entry,
        ct::SignedCertificateTimestamp::SCT_FROM_OCSP_RESPONSE, cert, result);

    has_verified_scts |= VerifySCTs(
        sct_list_from_tls_extension, x509_entry,
        ct::SignedCertificateTimestamp::SCT_FROM_TLS_EXTENSION, cert, result);
  }

  NetLog::ParametersCallback net_log_checked_callback =
      base::Bind(&NetLogSignedCertificateTimestampCallback, result);

  net_log.AddEvent(
      NetLog::TYPE_SIGNED_CERTIFICATE_TIMESTAMPS_CHECKED,
      net_log_checked_callback);

  LogNumSCTsToUMA(*result);

  if (has_verified_scts)
    return OK;

  return ERR_CT_NO_SCTS_VERIFIED_OK;
}

bool MultiLogCTVerifier::VerifySCTs(
    const std::string& encoded_sct_list,
    const ct::LogEntry& expected_entry,
    ct::SignedCertificateTimestamp::Origin origin,
    X509Certificate* cert,
    ct::CTVerifyResult* result) {
  if (logs_.empty())
    return false;

  base::StringPiece temp(encoded_sct_list);
  std::vector<base::StringPiece> sct_list;

  if (!ct::DecodeSCTList(&temp, &sct_list))
    return false;

  bool verified = false;
  for (std::vector<base::StringPiece>::const_iterator it = sct_list.begin();
       it != sct_list.end(); ++it) {
    base::StringPiece encoded_sct(*it);
    LogSCTOriginToUMA(origin);

    scoped_refptr<ct::SignedCertificateTimestamp> decoded_sct;
    if (!DecodeSignedCertificateTimestamp(&encoded_sct, &decoded_sct)) {
      LogSCTStatusToUMA(ct::SCT_STATUS_NONE);
      // XXX(rsleevi): Should we really just skip over bad SCTs?
      continue;
    }
    decoded_sct->origin = origin;

    verified |= VerifySingleSCT(decoded_sct, expected_entry, cert, result);
  }

  return verified;
}

bool MultiLogCTVerifier::VerifySingleSCT(
    scoped_refptr<ct::SignedCertificateTimestamp> sct,
    const ct::LogEntry& expected_entry,
    X509Certificate* cert,
    ct::CTVerifyResult* result) {
  // Assume this SCT is untrusted until proven otherwise.
  const auto& it = logs_.find(sct->log_id);
  if (it == logs_.end()) {
    DVLOG(1) << "SCT does not match any known log.";
    result->unknown_logs_scts.push_back(sct);
    LogSCTStatusToUMA(ct::SCT_STATUS_LOG_UNKNOWN);
    return false;
  }

  sct->log_description = it->second->description();

  if (!it->second->Verify(expected_entry, *sct.get())) {
    DVLOG(1) << "Unable to verify SCT signature.";
    result->invalid_scts.push_back(sct);
    LogSCTStatusToUMA(ct::SCT_STATUS_INVALID);
    return false;
  }

  // SCT verified ok, just make sure the timestamp is legitimate.
  if (sct->timestamp > base::Time::Now()) {
    DVLOG(1) << "SCT is from the future!";
    result->invalid_scts.push_back(sct);
    LogSCTStatusToUMA(ct::SCT_STATUS_INVALID);
    return false;
  }

  LogSCTStatusToUMA(ct::SCT_STATUS_OK);
  result->verified_scts.push_back(sct);
  if (observer_)
    observer_->OnSCTVerified(cert, sct.get());
  return true;
}

} // namespace net
