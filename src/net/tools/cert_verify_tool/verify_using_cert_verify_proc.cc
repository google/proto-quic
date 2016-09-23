// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/cert_verify_tool/verify_using_cert_verify_proc.h"

#include <iostream>

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "crypto/sha2.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/tools/cert_verify_tool/cert_verify_tool_util.h"

namespace {

// Associates a printable name with an integer constant. Useful for providing
// human-readable decoding of bitmask values.
struct StringToConstant {
  const char* name;
  const int constant;
};

const StringToConstant kCertStatusFlags[] = {
#define CERT_STATUS_FLAG(label, value) {#label, value},
#include "net/cert/cert_status_flags_list.h"
#undef CERT_STATUS_FLAG
};

// Writes a PEM-encoded file of |cert| and its chain.
bool DumpX509CertificateChain(const base::FilePath& file_path,
                              const net::X509Certificate* cert) {
  std::vector<std::string> pem_encoded;
  if (!cert->GetPEMEncodedChain(&pem_encoded)) {
    std::cerr << "ERROR: X509Certificate::GetPEMEncodedChain failed.\n";
    return false;
  }
  return WriteToFile(file_path, base::JoinString(pem_encoded, ""));
}

// Returns a hex-encoded sha256 of the DER-encoding of |cert_handle|.
std::string FingerPrintOSCertHandle(
    net::X509Certificate::OSCertHandle cert_handle) {
  net::SHA256HashValue hash =
      net::X509Certificate::CalculateFingerprint256(cert_handle);
  return base::HexEncode(hash.data, arraysize(hash.data));
}

// Returns a textual representation of the Subject of |cert|.
std::string SubjectFromX509Certificate(const net::X509Certificate* cert) {
  return cert->subject().GetDisplayName();
}

// Returns a textual representation of the Subject of |cert_handle|.
std::string SubjectFromOSCertHandle(
    net::X509Certificate::OSCertHandle cert_handle) {
  scoped_refptr<net::X509Certificate> cert =
      net::X509Certificate::CreateFromHandle(
          cert_handle, net::X509Certificate::OSCertHandles());
  return SubjectFromX509Certificate(cert.get());
}

void PrintCertStatus(int cert_status) {
  std::cout << base::StringPrintf("CertStatus: 0x%x\n", cert_status);

  for (const auto& flag : kCertStatusFlags) {
    if ((cert_status & flag.constant) == flag.constant)
      std::cout << " " << flag.name << "\n";
  }
}

void PrintCertVerifyResult(const net::CertVerifyResult& result) {
  PrintCertStatus(result.cert_status);
  if (result.has_md2)
    std::cout << "has_md2\n";
  if (result.has_md4)
    std::cout << "has_md4\n";
  if (result.has_md5)
    std::cout << "has_md5\n";
  if (result.has_sha1)
    std::cout << "has_sha1\n";
  if (result.has_sha1_leaf)
    std::cout << "has_sha1_leaf\n";
  if (result.is_issued_by_known_root)
    std::cout << "is_issued_by_known_root\n";
  if (result.is_issued_by_additional_trust_anchor)
    std::cout << "is_issued_by_additional_trust_anchor\n";
  if (result.common_name_fallback_used)
    std::cout << "common_name_fallback_used\n";

  if (result.verified_cert) {
    std::cout << "chain:\n "
              << FingerPrintOSCertHandle(result.verified_cert->os_cert_handle())
              << " " << SubjectFromX509Certificate(result.verified_cert.get())
              << "\n";
    for (auto* os_cert : result.verified_cert->GetIntermediateCertificates()) {
      std::cout << " " << FingerPrintOSCertHandle(os_cert) << " "
                << SubjectFromOSCertHandle(os_cert) << "\n";
    }
  }
}

}  // namespace

bool VerifyUsingCertVerifyProc(
    const CertInput& target_der_cert,
    const std::string& hostname,
    const std::vector<CertInput>& intermediate_der_certs,
    const std::vector<CertInput>& root_der_certs,
    const base::FilePath& dump_prefix_path) {
  std::cout
      << "NOTE: CertVerifyProc always uses OS trust settings (--roots are in "
         "addition).\n";

  std::vector<base::StringPiece> der_cert_chain;
  der_cert_chain.push_back(target_der_cert.der_cert);
  for (const auto& cert : intermediate_der_certs)
    der_cert_chain.push_back(cert.der_cert);

  scoped_refptr<net::X509Certificate> x509_target_and_intermediates =
      net::X509Certificate::CreateFromDERCertChain(der_cert_chain);
  if (!x509_target_and_intermediates) {
    std::cerr
        << "ERROR: X509Certificate::CreateFromDERCertChain failed on one or "
           "more of:\n";
    PrintCertError(" (target)", target_der_cert);
    for (const auto& cert : intermediate_der_certs)
      PrintCertError(" (intermediate)", cert);
    return false;
  }

  net::CertificateList x509_additional_trust_anchors;
  for (const auto& cert : root_der_certs) {
    scoped_refptr<net::X509Certificate> x509_root =
        net::X509Certificate::CreateFromBytes(cert.der_cert.data(),
                                              cert.der_cert.size());

    if (!x509_root)
      PrintCertError("ERROR: X509Certificate::CreateFromBytes failed:", cert);
    else
      x509_additional_trust_anchors.push_back(x509_root);
  }

  // TODO(mattm): add command line flags to configure VerifyFlags.
  int flags = net::CertVerifier::VERIFY_EV_CERT |
              net::CertVerifier::VERIFY_CERT_IO_ENABLED;

  scoped_refptr<net::CertVerifyProc> cert_verify_proc =
      net::CertVerifyProc::CreateDefault();
  if (!x509_additional_trust_anchors.empty() &&
      !cert_verify_proc->SupportsAdditionalTrustAnchors()) {
    std::cerr << "WARNING: Additional trust anchors not supported on this "
                 "platform.\n";
  }
  net::CertVerifyResult result;
  // TODO(mattm): add CRLSet handling.
  int rv = cert_verify_proc->Verify(x509_target_and_intermediates.get(),
                                    hostname, std::string() /* ocsp_response */,
                                    flags, nullptr /* crl_set */,
                                    x509_additional_trust_anchors, &result);

  std::cout << "CertVerifyProc result: " << net::ErrorToShortString(rv) << "\n";
  PrintCertVerifyResult(result);
  if (!dump_prefix_path.empty() && result.verified_cert) {
    if (!DumpX509CertificateChain(dump_prefix_path.AddExtension(
                                      FILE_PATH_LITERAL(".CertVerifyProc.pem")),
                                  result.verified_cert.get())) {
      return false;
    }
  }

  return rv == net::OK;
}
