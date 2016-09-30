// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_mac.h"

#include "base/logging.h"
#include "third_party/apple_apsl/cssmapplePriv.h"

namespace net {

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

namespace x509_util {

namespace {

// Creates a SecPolicyRef for the given OID, with optional value.
OSStatus CreatePolicy(const CSSM_OID* policy_oid,
                      void* option_data,
                      size_t option_length,
                      SecPolicyRef* policy) {
  SecPolicySearchRef search;
  OSStatus err = SecPolicySearchCreate(CSSM_CERT_X_509v3, policy_oid, NULL,
                                       &search);
  if (err)
    return err;
  err = SecPolicySearchCopyNext(search, policy);
  CFRelease(search);
  if (err)
    return err;

  if (option_data) {
    CSSM_DATA options_data = {
      option_length,
      reinterpret_cast<uint8_t*>(option_data)
    };
    err = SecPolicySetValue(*policy, &options_data);
    if (err) {
      CFRelease(*policy);
      return err;
    }
  }
  return noErr;
}

}  // namespace


OSStatus CreateSSLClientPolicy(SecPolicyRef* policy) {
  CSSM_APPLE_TP_SSL_OPTIONS tp_ssl_options;
  memset(&tp_ssl_options, 0, sizeof(tp_ssl_options));
  tp_ssl_options.Version = CSSM_APPLE_TP_SSL_OPTS_VERSION;
  tp_ssl_options.Flags |= CSSM_APPLE_TP_SSL_CLIENT;

  return CreatePolicy(&CSSMOID_APPLE_TP_SSL, &tp_ssl_options,
                      sizeof(tp_ssl_options), policy);
}

OSStatus CreateSSLServerPolicy(const std::string& hostname,
                               SecPolicyRef* policy) {
  CSSM_APPLE_TP_SSL_OPTIONS tp_ssl_options;
  memset(&tp_ssl_options, 0, sizeof(tp_ssl_options));
  tp_ssl_options.Version = CSSM_APPLE_TP_SSL_OPTS_VERSION;
  if (!hostname.empty()) {
    tp_ssl_options.ServerName = hostname.data();
    tp_ssl_options.ServerNameLen = hostname.size();
  }

  return CreatePolicy(&CSSMOID_APPLE_TP_SSL, &tp_ssl_options,
                      sizeof(tp_ssl_options), policy);
}

OSStatus CreateBasicX509Policy(SecPolicyRef* policy) {
  return CreatePolicy(&CSSMOID_APPLE_X509_BASIC, NULL, 0, policy);
}

OSStatus CreateRevocationPolicies(bool enable_revocation_checking,
                                  bool enable_ev_checking,
                                  CFMutableArrayRef policies) {
  OSStatus status = noErr;

  // In order to bypass the system revocation checking settings, the
  // SecTrustRef must have at least one revocation policy associated with it.
  // Since it is not known prior to verification whether the Apple TP will
  // consider a certificate as an EV candidate, the default policy used is a
  // CRL policy, since it does not communicate over the network.
  // If the TP believes the leaf is an EV cert, it will explicitly add an
  // OCSP policy to perform the online checking, and if it doesn't believe
  // that the leaf is EV, then the default CRL policy will effectively no-op.
  // This behaviour is used to implement EV-only revocation checking.
  if (enable_ev_checking || enable_revocation_checking) {
    CSSM_APPLE_TP_CRL_OPTIONS tp_crl_options;
    memset(&tp_crl_options, 0, sizeof(tp_crl_options));
    tp_crl_options.Version = CSSM_APPLE_TP_CRL_OPTS_VERSION;
    // Only allow network CRL fetches if the caller explicitly requests
    // online revocation checking. Note that, as of OS X 10.7.2, the system
    // will set force this flag on according to system policies, so
    // online revocation checks cannot be completely disabled.
    if (enable_revocation_checking)
      tp_crl_options.CrlFlags = CSSM_TP_ACTION_FETCH_CRL_FROM_NET;

    SecPolicyRef crl_policy;
    status = CreatePolicy(&CSSMOID_APPLE_TP_REVOCATION_CRL, &tp_crl_options,
                          sizeof(tp_crl_options), &crl_policy);
    if (status)
      return status;
    CFArrayAppendValue(policies, crl_policy);
    CFRelease(crl_policy);
  }

  // If revocation checking is explicitly enabled, then add an OCSP policy
  // and allow network access. If both revocation checking and EV checking
  // are disabled, then the added OCSP policy will be prevented from
  // accessing the network. This is done because the TP will force an OCSP
  // policy to be present when it believes the certificate is EV. If network
  // fetching was not explicitly disabled, then it would be as if
  // enable_ev_checking was always set to true.
  if (enable_revocation_checking || !enable_ev_checking) {
    CSSM_APPLE_TP_OCSP_OPTIONS tp_ocsp_options;
    memset(&tp_ocsp_options, 0, sizeof(tp_ocsp_options));
    tp_ocsp_options.Version = CSSM_APPLE_TP_OCSP_OPTS_VERSION;

    if (enable_revocation_checking) {
      // The default for the OCSP policy is to fetch responses via the network,
      // unlike the CRL policy default. The policy is further modified to
      // prefer OCSP over CRLs, if both are specified on the certificate. This
      // is because an OCSP response is both sufficient and typically
      // significantly smaller than the CRL counterpart.
      tp_ocsp_options.Flags = CSSM_TP_ACTION_OCSP_SUFFICIENT;
    } else {
      // Effectively disable OCSP checking by making it impossible to get an
      // OCSP response. Even if the Apple TP forces OCSP, no checking will
      // be able to succeed. If this happens, the Apple TP will report an error
      // that OCSP was unavailable, but this will be handled and suppressed in
      // X509Certificate::Verify().
      tp_ocsp_options.Flags = CSSM_TP_ACTION_OCSP_DISABLE_NET |
                              CSSM_TP_ACTION_OCSP_CACHE_READ_DISABLE;
    }

    SecPolicyRef ocsp_policy;
    status = CreatePolicy(&CSSMOID_APPLE_TP_REVOCATION_OCSP, &tp_ocsp_options,
                          sizeof(tp_ocsp_options), &ocsp_policy);
    if (status)
      return status;
    CFArrayAppendValue(policies, ocsp_policy);
    CFRelease(ocsp_policy);
  }

  return status;
}

CSSMFieldValue::CSSMFieldValue()
    : cl_handle_(CSSM_INVALID_HANDLE),
      oid_(NULL),
      field_(NULL) {
}
CSSMFieldValue::CSSMFieldValue(CSSM_CL_HANDLE cl_handle,
                               const CSSM_OID* oid,
                               CSSM_DATA_PTR field)
    : cl_handle_(cl_handle),
      oid_(const_cast<CSSM_OID_PTR>(oid)),
      field_(field) {
}

CSSMFieldValue::~CSSMFieldValue() {
  Reset(CSSM_INVALID_HANDLE, NULL, NULL);
}

void CSSMFieldValue::Reset(CSSM_CL_HANDLE cl_handle,
                           CSSM_OID_PTR oid,
                           CSSM_DATA_PTR field) {
  if (cl_handle_ && oid_ && field_)
    CSSM_CL_FreeFieldValue(cl_handle_, oid_, field_);
  cl_handle_ = cl_handle;
  oid_ = oid;
  field_ = field;
}

CSSMCachedCertificate::CSSMCachedCertificate()
    : cl_handle_(CSSM_INVALID_HANDLE),
      cached_cert_handle_(CSSM_INVALID_HANDLE) {
}
CSSMCachedCertificate::~CSSMCachedCertificate() {
  if (cl_handle_ && cached_cert_handle_)
    CSSM_CL_CertAbortCache(cl_handle_, cached_cert_handle_);
}

OSStatus CSSMCachedCertificate::Init(SecCertificateRef os_cert_handle) {
  DCHECK(!cl_handle_ && !cached_cert_handle_);
  DCHECK(os_cert_handle);
  CSSM_DATA cert_data;
  OSStatus status = SecCertificateGetData(os_cert_handle, &cert_data);
  if (status)
    return status;
  status = SecCertificateGetCLHandle(os_cert_handle, &cl_handle_);
  if (status) {
    DCHECK(!cl_handle_);
    return status;
  }

  status = CSSM_CL_CertCache(cl_handle_, &cert_data, &cached_cert_handle_);
  if (status)
    DCHECK(!cached_cert_handle_);
  return status;
}

OSStatus CSSMCachedCertificate::GetField(const CSSM_OID* field_oid,
                                         CSSMFieldValue* field) const {
  DCHECK(cl_handle_);
  DCHECK(cached_cert_handle_);

  CSSM_OID_PTR oid = const_cast<CSSM_OID_PTR>(field_oid);
  CSSM_DATA_PTR field_ptr = NULL;
  CSSM_HANDLE results_handle = CSSM_INVALID_HANDLE;
  uint32_t field_value_count = 0;
  CSSM_RETURN status = CSSM_CL_CertGetFirstCachedFieldValue(
      cl_handle_, cached_cert_handle_, oid, &results_handle,
      &field_value_count, &field_ptr);
  if (status)
    return status;

  // Note: |field_value_count| may be > 1, indicating that more than one
  // value is present. This may happen with extensions, but for current
  // usages, only the first value is returned.
  CSSM_CL_CertAbortQuery(cl_handle_, results_handle);
  field->Reset(cl_handle_, oid, field_ptr);
  return CSSM_OK;
}

}  // namespace x509_util

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"

}  // namespace net
