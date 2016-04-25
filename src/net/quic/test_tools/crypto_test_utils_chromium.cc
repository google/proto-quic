// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_data_directory.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/quic/crypto/crypto_utils.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/ssl/ssl_config_service.h"
#include "net/test/cert_test_util.h"

using base::StringPiece;
using base::StringPrintf;
using std::string;
using std::vector;

namespace net {

namespace test {

namespace {

class TestProofVerifierChromium : public ProofVerifierChromium {
 public:
  TestProofVerifierChromium(
      std::unique_ptr<CertVerifier> cert_verifier,
      std::unique_ptr<TransportSecurityState> transport_security_state,
      std::unique_ptr<CTVerifier> cert_transparency_verifier,
      const std::string& cert_file)
      : ProofVerifierChromium(cert_verifier.get(),
                              nullptr,
                              transport_security_state.get(),
                              cert_transparency_verifier.get()),
        cert_verifier_(std::move(cert_verifier)),
        transport_security_state_(std::move(transport_security_state)),
        cert_transparency_verifier_(std::move(cert_transparency_verifier)) {
    // Load and install the root for the validated chain.
    scoped_refptr<X509Certificate> root_cert =
        ImportCertFromFile(GetTestCertsDirectory(), cert_file);
    scoped_root_.Reset(root_cert.get());
  }

  ~TestProofVerifierChromium() override {}

  CertVerifier* cert_verifier() { return cert_verifier_.get(); }

 private:
  ScopedTestRoot scoped_root_;
  std::unique_ptr<CertVerifier> cert_verifier_;
  std::unique_ptr<TransportSecurityState> transport_security_state_;
  std::unique_ptr<CTVerifier> cert_transparency_verifier_;
};

}  // namespace

// static
ProofSource* CryptoTestUtils::ProofSourceForTesting() {
  ProofSourceChromium* source = new ProofSourceChromium();
  base::FilePath certs_dir = GetTestCertsDirectory();
  CHECK(source->Initialize(
      certs_dir.AppendASCII("quic_chain.crt"),
      certs_dir.AppendASCII("quic_test.example.com.key.pkcs8"),
      certs_dir.AppendASCII("quic_test.example.com.key.sct")));
  return source;
}

// static
ProofVerifier* ProofVerifierForTestingInternal(bool use_real_proof_verifier) {
  // TODO(rch): use a real cert verifier?
  std::unique_ptr<MockCertVerifier> cert_verifier(new MockCertVerifier());
  net::CertVerifyResult verify_result;
  verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "quic_test.example.com.crt");
  cert_verifier->AddResultForCertAndHost(verify_result.verified_cert.get(),
                                         "test.example.com", verify_result, OK);
  verify_result.verified_cert = ImportCertFromFile(
      GetTestCertsDirectory(), "quic_test_ecc.example.com.crt");
  cert_verifier->AddResultForCertAndHost(verify_result.verified_cert.get(),
                                         "test.example.com", verify_result, OK);
  if (use_real_proof_verifier) {
    return new TestProofVerifierChromium(
        std::move(cert_verifier), base::WrapUnique(new TransportSecurityState),
        base::WrapUnique(new MultiLogCTVerifier), "quic_root.crt");
  }
  return new TestProofVerifierChromium(
      std::move(cert_verifier), base::WrapUnique(new TransportSecurityState),
      base::WrapUnique(new MultiLogCTVerifier), "quic_root.crt");
}

// static
ProofVerifier* CryptoTestUtils::ProofVerifierForTesting() {
  return ProofVerifierForTestingInternal(/*use_real_proof_verifier=*/false);
}

// static
ProofVerifier* CryptoTestUtils::RealProofVerifierForTesting() {
  return ProofVerifierForTestingInternal(/*use_real_proof_verifier=*/true);
}

// static
ProofVerifyContext* CryptoTestUtils::ProofVerifyContextForTesting() {
  return new ProofVerifyContextChromium(/*cert_verify_flags=*/0, BoundNetLog());
}

}  // namespace test

}  // namespace net
