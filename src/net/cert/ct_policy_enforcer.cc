// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_policy_enforcer.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/build_time.h"
#include "base/callback_helpers.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "base/values.h"
#include "base/version.h"
#include "net/cert/ct_ev_whitelist.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_verify_result.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_parameters_callback.h"
#include "net/log/net_log_with_source.h"

namespace net {

namespace {

// Returns true if the current build is recent enough to ensure that
// built-in security information (e.g. CT Logs) is fresh enough.
// TODO(eranm): Move to base or net/base
bool IsBuildTimely() {
  const base::Time build_time = base::GetBuildTime();
  // We consider built-in information to be timely for 10 weeks.
  return (base::Time::Now() - build_time).InDays() < 70 /* 10 weeks */;
}

// Returns a rounded-down months difference of |start| and |end|,
// together with an indication of whether the last month was
// a full month, because the range starts specified in the policy
// are not consistent in terms of including the range start value.
void RoundedDownMonthDifference(const base::Time& start,
                                const base::Time& end,
                                size_t* rounded_months_difference,
                                bool* has_partial_month) {
  DCHECK(rounded_months_difference);
  DCHECK(has_partial_month);
  base::Time::Exploded exploded_start;
  base::Time::Exploded exploded_expiry;
  start.UTCExplode(&exploded_start);
  end.UTCExplode(&exploded_expiry);
  if (end < start) {
    *rounded_months_difference = 0;
    *has_partial_month = false;
  }

  *has_partial_month = true;
  uint32_t month_diff = (exploded_expiry.year - exploded_start.year) * 12 +
                        (exploded_expiry.month - exploded_start.month);
  if (exploded_expiry.day_of_month < exploded_start.day_of_month)
    --month_diff;
  else if (exploded_expiry.day_of_month == exploded_start.day_of_month)
    *has_partial_month = false;

  *rounded_months_difference = month_diff;
}

const char* EVPolicyComplianceToString(ct::EVPolicyCompliance status) {
  switch (status) {
    case ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY:
      return "POLICY_DOES_NOT_APPLY";
    case ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_WHITELIST:
      return "WHITELISTED";
    case ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS:
      return "COMPLIES_VIA_SCTS";
    case ct::EVPolicyCompliance::EV_POLICY_NOT_ENOUGH_SCTS:
      return "NOT_ENOUGH_SCTS";
    case ct::EVPolicyCompliance::EV_POLICY_NOT_DIVERSE_SCTS:
      return "SCTS_NOT_DIVERSE";
    case ct::EVPolicyCompliance::EV_POLICY_BUILD_NOT_TIMELY:
      return "BUILD_NOT_TIMELY";
    case ct::EVPolicyCompliance::EV_POLICY_MAX:
      break;
  }

  return "unknown";
}

const char* CertPolicyComplianceToString(ct::CertPolicyCompliance status) {
  switch (status) {
    case ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS:
      return "COMPLIES_VIA_SCTS";
    case ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS:
      return "NOT_ENOUGH_SCTS";
    case ct::CertPolicyCompliance::CERT_POLICY_NOT_DIVERSE_SCTS:
      return "NOT_DIVERSE_SCTS";
    case ct::CertPolicyCompliance::CERT_POLICY_BUILD_NOT_TIMELY:
      return "BUILD_NOT_TIMELY";
  }

  return "unknown";
}

enum EVWhitelistStatus {
  EV_WHITELIST_NOT_PRESENT = 0,
  EV_WHITELIST_INVALID = 1,
  EV_WHITELIST_VALID = 2,
  EV_WHITELIST_MAX,
};

void LogEVPolicyComplianceToUMA(ct::EVPolicyCompliance status,
                                const ct::EVCertsWhitelist* ev_whitelist) {
  UMA_HISTOGRAM_ENUMERATION(
      "Net.SSL_EVCTCompliance", static_cast<int>(status),
      static_cast<int>(ct::EVPolicyCompliance::EV_POLICY_MAX));
  if (status == ct::EVPolicyCompliance::EV_POLICY_NOT_ENOUGH_SCTS ||
      status == ct::EVPolicyCompliance::EV_POLICY_NOT_DIVERSE_SCTS) {
    EVWhitelistStatus ev_whitelist_status = EV_WHITELIST_NOT_PRESENT;
    if (ev_whitelist != NULL) {
      if (ev_whitelist->IsValid())
        ev_whitelist_status = EV_WHITELIST_VALID;
      else
        ev_whitelist_status = EV_WHITELIST_INVALID;
    }

    UMA_HISTOGRAM_ENUMERATION("Net.SSL_EVWhitelistValidityForNonCompliantCert",
                              ev_whitelist_status, EV_WHITELIST_MAX);
  }
}

struct EVComplianceDetails {
  EVComplianceDetails()
      : build_timely(false),
        status(ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY) {}

  // Whether the build is not older than 10 weeks.
  bool build_timely;
  // Compliance status - meaningful only if |build_timely| is true.
  ct::EVPolicyCompliance status;
  // EV whitelist version.
  base::Version whitelist_version;
};

std::unique_ptr<base::Value> NetLogEVComplianceCheckResultCallback(
    X509Certificate* cert,
    EVComplianceDetails* details,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->Set("certificate", NetLogX509CertificateCallback(cert, capture_mode));
  dict->SetBoolean("policy_enforcement_required", true);
  dict->SetBoolean("build_timely", details->build_timely);
  if (details->build_timely) {
    dict->SetString("ct_compliance_status",
                    EVPolicyComplianceToString(details->status));
    if (details->whitelist_version.IsValid())
      dict->SetString("ev_whitelist_version",
                      details->whitelist_version.GetString());
  }
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogCertComplianceCheckResultCallback(
    X509Certificate* cert,
    bool build_timely,
    ct::CertPolicyCompliance compliance,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->Set("certificate", NetLogX509CertificateCallback(cert, capture_mode));
  dict->SetBoolean("build_timely", build_timely);
  dict->SetString("ct_compliance_status",
                  CertPolicyComplianceToString(compliance));
  return std::move(dict);
}

bool IsCertificateInWhitelist(const X509Certificate& cert,
                              const ct::EVCertsWhitelist* ev_whitelist) {
  if (!ev_whitelist || !ev_whitelist->IsValid())
    return false;

  const SHA256HashValue fingerprint(
      X509Certificate::CalculateFingerprint256(cert.os_cert_handle()));

  std::string truncated_fp =
      std::string(reinterpret_cast<const char*>(fingerprint.data), 8);
  bool cert_in_ev_whitelist =
      ev_whitelist->ContainsCertificateHash(truncated_fp);

  UMA_HISTOGRAM_BOOLEAN("Net.SSL_EVCertificateInWhitelist",
                        cert_in_ev_whitelist);
  return cert_in_ev_whitelist;
}

// Evaluates against the policy specified at
// https://sites.google.com/a/chromium.org/dev/Home/chromium-security/root-ca-policy/EVCTPlanMay2015edition.pdf?attredirects=0
ct::CertPolicyCompliance CheckCertPolicyCompliance(
    const X509Certificate& cert,
    const ct::SCTList& verified_scts) {
  // Cert is outside the bounds of parsable; reject it.
  if (cert.valid_start().is_null() || cert.valid_expiry().is_null() ||
      cert.valid_start().is_max() || cert.valid_expiry().is_max()) {
    return ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS;
  }

  // Scan for the earliest SCT. This is used to determine whether to enforce
  // log diversity requirements, as well as whether to enforce whether or not
  // a log was qualified or pending qualification at time of issuance (in the
  // case of embedded SCTs). It's acceptable to ignore the origin of the SCT,
  // because SCTs delivered via OCSP/TLS extension will cover the full
  // certificate, which necessarily will exist only after the precertificate
  // has been logged and the actual certificate issued.
  // Note: Here, issuance date is defined as the earliest of all SCTs, rather
  // than the latest of embedded SCTs, in order to give CAs the benefit of
  // the doubt in the event a log is revoked in the midst of processing
  // a precertificate and issuing the certificate.
  base::Time issuance_date = base::Time::Max();
  for (const auto& sct : verified_scts) {
    base::Time unused;
    if (ct::IsLogDisqualified(sct->log_id, &unused))
      continue;
    issuance_date = std::min(sct->timestamp, issuance_date);
  }

  bool has_valid_google_sct = false;
  bool has_valid_nongoogle_sct = false;
  bool has_valid_embedded_sct = false;
  bool has_valid_nonembedded_sct = false;
  bool has_embedded_google_sct = false;
  bool has_embedded_nongoogle_sct = false;
  std::vector<base::StringPiece> embedded_log_ids;
  for (const auto& sct : verified_scts) {
    base::Time disqualification_date;
    bool is_disqualified =
        ct::IsLogDisqualified(sct->log_id, &disqualification_date);
    if (is_disqualified &&
        sct->origin != ct::SignedCertificateTimestamp::SCT_EMBEDDED) {
      // For OCSP and TLS delivered SCTs, only SCTs that are valid at the
      // time of check are accepted.
      continue;
    }

    if (ct::IsLogOperatedByGoogle(sct->log_id)) {
      has_valid_google_sct |= !is_disqualified;
      if (sct->origin == ct::SignedCertificateTimestamp::SCT_EMBEDDED)
        has_embedded_google_sct = true;
    } else {
      has_valid_nongoogle_sct |= !is_disqualified;
      if (sct->origin == ct::SignedCertificateTimestamp::SCT_EMBEDDED)
        has_embedded_nongoogle_sct = true;
    }
    if (sct->origin != ct::SignedCertificateTimestamp::SCT_EMBEDDED) {
      has_valid_nonembedded_sct = true;
    } else {
      has_valid_embedded_sct |= !is_disqualified;
      // If the log is disqualified, it only counts towards quorum if
      // the certificate was issued before the log was disqualified, and the
      // SCT was obtained before the log was disqualified.
      if (!is_disqualified || (issuance_date < disqualification_date &&
                               sct->timestamp < disqualification_date)) {
        embedded_log_ids.push_back(sct->log_id);
      }
    }
  }

  // Option 1:
  // An SCT presented via the TLS extension OR embedded within a stapled OCSP
  //   response is from a log qualified at time of check;
  // AND there is at least one SCT from a Google Log that is qualified at
  //   time of check, presented via any method;
  // AND there is at least one SCT from a non-Google Log that is qualified
  //   at the time of check, presented via any method.
  //
  // Note: Because SCTs embedded via TLS or OCSP can be updated on the fly,
  // the issuance date is irrelevant, as any policy changes can be
  // accomodated.
  if (has_valid_nonembedded_sct && has_valid_google_sct &&
      has_valid_nongoogle_sct) {
    return ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS;
  }
  // Note: If has_valid_nonembedded_sct was true, but Option 2 isn't met,
  // then the result will be that there weren't diverse enough SCTs, as that
  // the only other way for the conditional above to fail). Because Option 1
  // has the diversity requirement, it's implicitly a minimum number of SCTs
  // (specifically, 2), but that's not explicitly specified in the policy.

  // Option 2:
  // There is at least one embedded SCT from a log qualified at the time of
  //   check ...
  if (!has_valid_embedded_sct) {
    // Under Option 2, there weren't enough SCTs, and potentially under
    // Option 1, there weren't diverse enough SCTs. Try to signal the error
    // that is most easily fixed.
    return has_valid_nonembedded_sct
               ? ct::CertPolicyCompliance::CERT_POLICY_NOT_DIVERSE_SCTS
               : ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS;
  }

  // ... AND there is at least one embedded SCT from a Google Log once or
  //   currently qualified;
  // AND there is at least one embedded SCT from a non-Google Log once or
  //   currently qualified;
  // ...
  //
  // Note: This policy language is only enforced after the below issuance
  // date, as that's when the diversity policy first came into effect for
  // SCTs embedded in certificates.
  // The date when diverse SCTs requirement is effective from.
  // 2015-07-01 00:00:00 UTC.
  const base::Time kDiverseSCTRequirementStartDate =
      base::Time::FromInternalValue(INT64_C(13080182400000000));
  if (issuance_date >= kDiverseSCTRequirementStartDate &&
      !(has_embedded_google_sct && has_embedded_nongoogle_sct)) {
    // Note: This also covers the case for non-embedded SCTs, as it's only
    // possible to reach here if both sets are not diverse enough.
    return ct::CertPolicyCompliance::CERT_POLICY_NOT_DIVERSE_SCTS;
  }

  size_t lifetime_in_months = 0;
  bool has_partial_month = false;
  RoundedDownMonthDifference(cert.valid_start(), cert.valid_expiry(),
                             &lifetime_in_months, &has_partial_month);

  // ... AND the certificate embeds SCTs from AT LEAST the number of logs
  //   once or currently qualified shown in Table 1 of the CT Policy.
  size_t num_required_embedded_scts = 5;
  if (lifetime_in_months > 39 ||
      (lifetime_in_months == 39 && has_partial_month)) {
    num_required_embedded_scts = 5;
  } else if (lifetime_in_months > 27 ||
             (lifetime_in_months == 27 && has_partial_month)) {
    num_required_embedded_scts = 4;
  } else if (lifetime_in_months >= 15) {
    num_required_embedded_scts = 3;
  } else {
    num_required_embedded_scts = 2;
  }

  // Sort the embedded log IDs and remove duplicates, so that only a single
  // SCT from each log is accepted. This is to handle the case where a given
  // log returns different SCTs for the same precertificate (which is
  // permitted, but advised against).
  std::sort(embedded_log_ids.begin(), embedded_log_ids.end());
  auto sorted_end =
      std::unique(embedded_log_ids.begin(), embedded_log_ids.end());
  size_t num_embedded_scts =
      std::distance(embedded_log_ids.begin(), sorted_end);

  if (num_embedded_scts >= num_required_embedded_scts)
    return ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS;

  // Under Option 2, there weren't enough SCTs, and potentially under Option
  // 1, there weren't diverse enough SCTs. Try to signal the error that is
  // most easily fixed.
  return has_valid_nonembedded_sct
             ? ct::CertPolicyCompliance::CERT_POLICY_NOT_DIVERSE_SCTS
             : ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS;
}

ct::EVPolicyCompliance CertPolicyComplianceToEVPolicyCompliance(
    ct::CertPolicyCompliance cert_policy_compliance) {
  switch (cert_policy_compliance) {
    case ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS:
      return ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS;
    case ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS:
      return ct::EVPolicyCompliance::EV_POLICY_NOT_ENOUGH_SCTS;
    case ct::CertPolicyCompliance::CERT_POLICY_NOT_DIVERSE_SCTS:
      return ct::EVPolicyCompliance::EV_POLICY_NOT_DIVERSE_SCTS;
    case ct::CertPolicyCompliance::CERT_POLICY_BUILD_NOT_TIMELY:
      return ct::EVPolicyCompliance::EV_POLICY_BUILD_NOT_TIMELY;
  }
  return ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY;
}

void CheckCTEVPolicyCompliance(X509Certificate* cert,
                               const ct::EVCertsWhitelist* ev_whitelist,
                               const ct::SCTList& verified_scts,
                               const NetLogWithSource& net_log,
                               EVComplianceDetails* result) {
  result->status = CertPolicyComplianceToEVPolicyCompliance(
      CheckCertPolicyCompliance(*cert, verified_scts));
  if (ev_whitelist && ev_whitelist->IsValid())
    result->whitelist_version = ev_whitelist->Version();

  if (result->status != ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS &&
      IsCertificateInWhitelist(*cert, ev_whitelist)) {
    result->status = ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_WHITELIST;
  }
}

}  // namespace

ct::CertPolicyCompliance CTPolicyEnforcer::DoesConformToCertPolicy(
    X509Certificate* cert,
    const ct::SCTList& verified_scts,
    const NetLogWithSource& net_log) {
  // If the build is not timely, no certificate is considered compliant
  // with CT policy. The reasoning is that, for example, a log might
  // have been pulled and is no longer considered valid; thus, a client
  // needs up-to-date information about logs to consider certificates to
  // be compliant with policy.
  bool build_timely = IsBuildTimely();
  ct::CertPolicyCompliance compliance;
  if (!build_timely) {
    compliance = ct::CertPolicyCompliance::CERT_POLICY_BUILD_NOT_TIMELY;
  } else {
    compliance = CheckCertPolicyCompliance(*cert, verified_scts);
  }

  NetLogParametersCallback net_log_callback =
      base::Bind(&NetLogCertComplianceCheckResultCallback,
                 base::Unretained(cert), build_timely, compliance);

  net_log.AddEvent(NetLogEventType::CERT_CT_COMPLIANCE_CHECKED,
                   net_log_callback);

  return compliance;
}

ct::EVPolicyCompliance CTPolicyEnforcer::DoesConformToCTEVPolicy(
    X509Certificate* cert,
    const ct::EVCertsWhitelist* ev_whitelist,
    const ct::SCTList& verified_scts,
    const NetLogWithSource& net_log) {
  EVComplianceDetails details;
  // If the build is not timely, no certificate is considered compliant
  // with EV policy. The reasoning is that, for example, a log might
  // have been pulled and is no longer considered valid; thus, a client
  // needs up-to-date information about logs to consider certificates to
  // be compliant with policy.
  details.build_timely = IsBuildTimely();
  if (!details.build_timely) {
    details.status = ct::EVPolicyCompliance::EV_POLICY_BUILD_NOT_TIMELY;
  } else {
    CheckCTEVPolicyCompliance(cert, ev_whitelist, verified_scts, net_log,
                              &details);
  }

  NetLogParametersCallback net_log_callback =
      base::Bind(&NetLogEVComplianceCheckResultCallback, base::Unretained(cert),
                 base::Unretained(&details));

  net_log.AddEvent(NetLogEventType::EV_CERT_CT_COMPLIANCE_CHECKED,
                   net_log_callback);

  if (!details.build_timely)
    return ct::EVPolicyCompliance::EV_POLICY_BUILD_NOT_TIMELY;

  LogEVPolicyComplianceToUMA(details.status, ev_whitelist);

  return details.status;
}

}  // namespace net
