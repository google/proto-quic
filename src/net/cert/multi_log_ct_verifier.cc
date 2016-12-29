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
#include "net/cert/sct_status_flags.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/x509_certificate.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_parameters_callback.h"
#include "net/log/net_log_with_source.h"

namespace net {

namespace {

// Record SCT verification status. This metric would help detecting presence
// of unknown CT logs as well as bad deployments (invalid SCTs).
void LogSCTStatusToUMA(ct::SCTVerifyStatus status) {
  // Note SCT_STATUS_MAX + 1 is passed to the UMA_HISTOGRAM_ENUMERATION as that
  // macro requires the values to be strictly less than the boundary value,
  // and SCT_STATUS_MAX is the last valid value of the SCTVerifyStatus enum
  // (since that enum is used for IPC as well).
  UMA_HISTOGRAM_ENUMERATION("Net.CertificateTransparency.SCTStatus", status,
                            ct::SCT_STATUS_MAX + 1);
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
void LogNumSCTsToUMA(const SignedCertificateTimestampAndStatusList& scts) {
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.CertificateTransparency.SCTsPerConnection",
                              scts.size(), 1, 10, 11);
}

void AddSCTAndLogStatus(scoped_refptr<ct::SignedCertificateTimestamp> sct,
                        ct::SCTVerifyStatus status,
                        SignedCertificateTimestampAndStatusList* sct_list) {
  LogSCTStatusToUMA(status);
  sct_list->push_back(SignedCertificateTimestampAndStatus(sct, status));
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

void MultiLogCTVerifier::Verify(
    X509Certificate* cert,
    base::StringPiece stapled_ocsp_response,
    base::StringPiece sct_list_from_tls_extension,
    SignedCertificateTimestampAndStatusList* output_scts,
    const NetLogWithSource& net_log) {
  DCHECK(cert);
  DCHECK(output_scts);

  output_scts->clear();

  std::string embedded_scts;
  if (!cert->GetIntermediateCertificates().empty() &&
      ct::ExtractEmbeddedSCTList(
          cert->os_cert_handle(),
          &embedded_scts)) {
    ct::LogEntry precert_entry;

    if (ct::GetPrecertLogEntry(cert->os_cert_handle(),
                               cert->GetIntermediateCertificates().front(),
                               &precert_entry)) {
      VerifySCTs(embedded_scts, precert_entry,
                 ct::SignedCertificateTimestamp::SCT_EMBEDDED, cert,
                 output_scts);
    }
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
  NetLogParametersCallback net_log_callback =
      base::Bind(&NetLogRawSignedCertificateTimestampCallback, embedded_scts,
                 sct_list_from_ocsp, sct_list_from_tls_extension);

  net_log.AddEvent(NetLogEventType::SIGNED_CERTIFICATE_TIMESTAMPS_RECEIVED,
                   net_log_callback);

  ct::LogEntry x509_entry;
  if (ct::GetX509LogEntry(cert->os_cert_handle(), &x509_entry)) {
    VerifySCTs(sct_list_from_ocsp, x509_entry,
               ct::SignedCertificateTimestamp::SCT_FROM_OCSP_RESPONSE, cert,
               output_scts);

    VerifySCTs(sct_list_from_tls_extension, x509_entry,
               ct::SignedCertificateTimestamp::SCT_FROM_TLS_EXTENSION, cert,
               output_scts);
  }

  NetLogParametersCallback net_log_checked_callback =
      base::Bind(&NetLogSignedCertificateTimestampCallback, output_scts);

  net_log.AddEvent(NetLogEventType::SIGNED_CERTIFICATE_TIMESTAMPS_CHECKED,
                   net_log_checked_callback);

  LogNumSCTsToUMA(*output_scts);
}

void MultiLogCTVerifier::VerifySCTs(
    base::StringPiece encoded_sct_list,
    const ct::LogEntry& expected_entry,
    ct::SignedCertificateTimestamp::Origin origin,
    X509Certificate* cert,
    SignedCertificateTimestampAndStatusList* output_scts) {
  if (logs_.empty())
    return;

  std::vector<base::StringPiece> sct_list;

  if (!ct::DecodeSCTList(encoded_sct_list, &sct_list))
    return;

  for (std::vector<base::StringPiece>::const_iterator it = sct_list.begin();
       it != sct_list.end(); ++it) {
    base::StringPiece encoded_sct(*it);
    LogSCTOriginToUMA(origin);

    scoped_refptr<ct::SignedCertificateTimestamp> decoded_sct;
    if (!DecodeSignedCertificateTimestamp(&encoded_sct, &decoded_sct)) {
      LogSCTStatusToUMA(ct::SCT_STATUS_NONE);
      continue;
    }
    decoded_sct->origin = origin;

    VerifySingleSCT(decoded_sct, expected_entry, cert, output_scts);
  }
}

bool MultiLogCTVerifier::VerifySingleSCT(
    scoped_refptr<ct::SignedCertificateTimestamp> sct,
    const ct::LogEntry& expected_entry,
    X509Certificate* cert,
    SignedCertificateTimestampAndStatusList* output_scts) {
  // Assume this SCT is untrusted until proven otherwise.
  const auto& it = logs_.find(sct->log_id);
  if (it == logs_.end()) {
    DVLOG(1) << "SCT does not match any known log.";
    AddSCTAndLogStatus(sct, ct::SCT_STATUS_LOG_UNKNOWN, output_scts);
    return false;
  }

  sct->log_description = it->second->description();

  if (!it->second->Verify(expected_entry, *sct.get())) {
    DVLOG(1) << "Unable to verify SCT signature.";
    AddSCTAndLogStatus(sct, ct::SCT_STATUS_INVALID_SIGNATURE, output_scts);
    return false;
  }

  // SCT verified ok, just make sure the timestamp is legitimate.
  if (sct->timestamp > base::Time::Now()) {
    DVLOG(1) << "SCT is from the future!";
    AddSCTAndLogStatus(sct, ct::SCT_STATUS_INVALID_TIMESTAMP, output_scts);
    return false;
  }

  AddSCTAndLogStatus(sct, ct::SCT_STATUS_OK, output_scts);
  if (observer_)
    observer_->OnSCTVerified(cert, sct.get());
  return true;
}

} // namespace net
