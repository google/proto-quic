// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_policy_enforcer.h"

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
#include "net/log/net_log.h"

namespace net {

namespace {

bool IsEmbeddedSCT(const scoped_refptr<ct::SignedCertificateTimestamp>& sct) {
  return sct->origin == ct::SignedCertificateTimestamp::SCT_EMBEDDED;
}

// Returns true if the current build is recent enough to ensure that
// built-in security information (e.g. CT Logs) is fresh enough.
// TODO(eranm): Move to base or net/base
bool IsBuildTimely() {
  const base::Time build_time = base::GetBuildTime();
  // We consider built-in information to be timely for 10 weeks.
  return (base::Time::Now() - build_time).InDays() < 70 /* 10 weeks */;
}

bool IsGoogleIssuedSCT(
    const scoped_refptr<ct::SignedCertificateTimestamp>& sct) {
  return ct::IsLogOperatedByGoogle(sct->log_id);
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

bool HasRequiredNumberOfSCTs(const X509Certificate& cert,
                             const ct::SCTList& verified_scts) {
  size_t num_valid_scts = verified_scts.size();
  size_t num_embedded_scts = base::checked_cast<size_t>(
      std::count_if(verified_scts.begin(), verified_scts.end(), IsEmbeddedSCT));

  size_t num_non_embedded_scts = num_valid_scts - num_embedded_scts;
  // If at least two valid SCTs were delivered by means other than embedding
  // (i.e. in a TLS extension or OCSP), then the certificate conforms to bullet
  // number 3 of the "Qualifying Certificate" section of the CT/EV policy.
  if (num_non_embedded_scts >= 2)
    return true;

  if (cert.valid_start().is_null() || cert.valid_expiry().is_null() ||
      cert.valid_start().is_max() || cert.valid_expiry().is_max()) {
    // Will not be able to calculate the certificate's validity period.
    return false;
  }

  size_t lifetime;
  bool has_partial_month;
  RoundedDownMonthDifference(cert.valid_start(), cert.valid_expiry(), &lifetime,
                             &has_partial_month);

  // For embedded SCTs, if the certificate has the number of SCTs specified in
  // table 1 of the "Qualifying Certificate" section of the CT/EV policy, then
  // it qualifies.
  size_t num_required_embedded_scts;
  if (lifetime > 39 || (lifetime == 39 && has_partial_month)) {
    num_required_embedded_scts = 5;
  } else if (lifetime > 27 || (lifetime == 27 && has_partial_month)) {
    num_required_embedded_scts = 4;
  } else if (lifetime >= 15) {
    num_required_embedded_scts = 3;
  } else {
    num_required_embedded_scts = 2;
  }

  return num_embedded_scts >= num_required_embedded_scts;
}

// Returns true if |verified_scts| contains SCTs from at least one log that is
// operated by Google and at least one log that is not operated by Google. This
// is required for SCTs after July 1st, 2015, as documented at
// http://dev.chromium.org/Home/chromium-security/root-ca-policy/EVCTPlanMay2015edition.pdf
bool HasEnoughDiverseSCTs(const ct::SCTList& verified_scts) {
  size_t num_google_issued_scts = base::checked_cast<size_t>(std::count_if(
      verified_scts.begin(), verified_scts.end(), IsGoogleIssuedSCT));
  return (num_google_issued_scts > 0) &&
         (verified_scts.size() != num_google_issued_scts);
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

// Returns true if all SCTs in |verified_scts| were issued on, or after, the
// date specified in kDiverseSCTRequirementStartDate
bool AllSCTsPastDistinctSCTRequirementEnforcementDate(
    const ct::SCTList& verified_scts) {
  // The date when diverse SCTs requirement is effective from.
  // 2015-07-01 00:00:00 UTC.
  base::Time kDiverseSCTRequirementStartDate =
      base::Time::FromInternalValue(13080182400000000);

  for (const auto& it : verified_scts) {
    if (it->timestamp < kDiverseSCTRequirementStartDate)
      return false;
  }

  return true;
}

bool IsCertificateInWhitelist(const X509Certificate& cert,
                              const ct::EVCertsWhitelist* ev_whitelist) {
  bool cert_in_ev_whitelist = false;
  if (ev_whitelist && ev_whitelist->IsValid()) {
    const SHA256HashValue fingerprint(
        X509Certificate::CalculateFingerprint256(cert.os_cert_handle()));

    std::string truncated_fp =
        std::string(reinterpret_cast<const char*>(fingerprint.data), 8);
    cert_in_ev_whitelist = ev_whitelist->ContainsCertificateHash(truncated_fp);

    UMA_HISTOGRAM_BOOLEAN("Net.SSL_EVCertificateInWhitelist",
                          cert_in_ev_whitelist);
  }
  return cert_in_ev_whitelist;
}

ct::CertPolicyCompliance CheckCertPolicyCompliance(
    X509Certificate* cert,
    const ct::SCTList& verified_scts,
    const BoundNetLog& net_log) {
  if (!HasRequiredNumberOfSCTs(*cert, verified_scts))
    return ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS;
  if (AllSCTsPastDistinctSCTRequirementEnforcementDate(verified_scts) &&
      !HasEnoughDiverseSCTs(verified_scts)) {
    return ct::CertPolicyCompliance::CERT_POLICY_NOT_DIVERSE_SCTS;
  }

  return ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS;
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
                               const BoundNetLog& net_log,
                               EVComplianceDetails* result) {
  result->status = CertPolicyComplianceToEVPolicyCompliance(
      CheckCertPolicyCompliance(cert, verified_scts, net_log));
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
    const BoundNetLog& net_log) {
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
    compliance = CheckCertPolicyCompliance(cert, verified_scts, net_log);
  }

  NetLog::ParametersCallback net_log_callback =
      base::Bind(&NetLogCertComplianceCheckResultCallback,
                 base::Unretained(cert), build_timely, compliance);

  net_log.AddEvent(NetLog::TYPE_CERT_CT_COMPLIANCE_CHECKED, net_log_callback);

  return compliance;
}

ct::EVPolicyCompliance CTPolicyEnforcer::DoesConformToCTEVPolicy(
    X509Certificate* cert,
    const ct::EVCertsWhitelist* ev_whitelist,
    const ct::SCTList& verified_scts,
    const BoundNetLog& net_log) {
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

  NetLog::ParametersCallback net_log_callback =
      base::Bind(&NetLogEVComplianceCheckResultCallback, base::Unretained(cert),
                 base::Unretained(&details));

  net_log.AddEvent(NetLog::TYPE_EV_CERT_CT_COMPLIANCE_CHECKED,
                   net_log_callback);

  if (!details.build_timely)
    return ct::EVPolicyCompliance::EV_POLICY_BUILD_NOT_TIMELY;

  LogEVPolicyComplianceToUMA(details.status, ev_whitelist);

  return details.status;
}

}  // namespace net
