// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_config.h"

#include "net/cert/cert_verifier.h"

namespace net {

const uint16_t kDefaultSSLVersionMin = SSL_PROTOCOL_VERSION_TLS1;

const uint16_t kDefaultSSLVersionMax = SSL_PROTOCOL_VERSION_TLS1_2;

const uint16_t kDefaultSSLVersionFallbackMin = SSL_PROTOCOL_VERSION_TLS1_2;

SSLConfig::CertAndStatus::CertAndStatus() : cert_status(0) {}

SSLConfig::CertAndStatus::~CertAndStatus() {}

SSLConfig::SSLConfig()
    : rev_checking_enabled(false),
      rev_checking_required_local_anchors(false),
      version_min(kDefaultSSLVersionMin),
      version_max(kDefaultSSLVersionMax),
      version_fallback_min(kDefaultSSLVersionFallbackMin),
      deprecated_cipher_suites_enabled(false),
      dhe_enabled(false),
      channel_id_enabled(true),
      false_start_enabled(true),
      signed_cert_timestamps_enabled(true),
      require_ecdhe(false),
      send_client_cert(false),
      verify_ev_cert(false),
      version_fallback(false),
      cert_io_enabled(true),
      renego_allowed_default(false) {}

SSLConfig::SSLConfig(const SSLConfig& other) = default;

SSLConfig::~SSLConfig() {}

bool SSLConfig::IsAllowedBadCert(X509Certificate* cert,
                                 CertStatus* cert_status) const {
  std::string der_cert;
  if (!X509Certificate::GetDEREncoded(cert->os_cert_handle(), &der_cert))
    return false;
  return IsAllowedBadCert(der_cert, cert_status);
}

bool SSLConfig::IsAllowedBadCert(const base::StringPiece& der_cert,
                                 CertStatus* cert_status) const {
  for (size_t i = 0; i < allowed_bad_certs.size(); ++i) {
    if (der_cert == allowed_bad_certs[i].der_cert) {
      if (cert_status)
        *cert_status = allowed_bad_certs[i].cert_status;
      return true;
    }
  }
  return false;
}

int SSLConfig::GetCertVerifyFlags() const {
  int flags = 0;
  if (rev_checking_enabled)
    flags |= CertVerifier::VERIFY_REV_CHECKING_ENABLED;
  if (verify_ev_cert)
    flags |= CertVerifier::VERIFY_EV_CERT;
  if (cert_io_enabled)
    flags |= CertVerifier::VERIFY_CERT_IO_ENABLED;
  if (rev_checking_required_local_anchors)
    flags |= CertVerifier::VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS;
  return flags;
}

}  // namespace net
