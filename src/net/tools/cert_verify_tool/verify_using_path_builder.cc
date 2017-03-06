// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/cert_verify_tool/verify_using_path_builder.h"

#include <iostream>

#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "crypto/sha2.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/internal/cert_issuer_source_aia.h"
#include "net/cert/internal/cert_issuer_source_static.h"
#include "net/cert/internal/parse_name.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/path_builder.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store_collection.h"
#include "net/cert/internal/trust_store_in_memory.h"
#include "net/cert/x509_util.h"
#include "net/cert_net/cert_net_fetcher_impl.h"
#include "net/tools/cert_verify_tool/cert_verify_tool_util.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_context_getter.h"

#if defined(USE_NSS_CERTS)
#include "base/threading/thread_task_runner_handle.h"
#include "net/cert/internal/cert_issuer_source_nss.h"
#include "net/cert/internal/trust_store_nss.h"
#endif

#if defined(OS_LINUX)
#include "net/proxy/proxy_config.h"
#include "net/proxy/proxy_config_service_fixed.h"
#endif

#if defined(OS_MACOSX) && !defined(OS_IOS)
#include <Security/Security.h>
#include "net/cert/internal/trust_store_mac.h"
#endif

namespace {

std::string GetUserAgent() {
  return "cert_verify_tool/0.1";
}

// Converts a base::Time::Exploded to a net::der::GeneralizedTime.
// TODO(mattm): This function exists in cast_cert_validator.cc also. Dedupe it?
net::der::GeneralizedTime ConvertExplodedTime(
    const base::Time::Exploded& exploded) {
  net::der::GeneralizedTime result;
  result.year = exploded.year;
  result.month = exploded.month;
  result.day = exploded.day_of_month;
  result.hours = exploded.hour;
  result.minutes = exploded.minute;
  result.seconds = exploded.second;
  return result;
}

bool AddPemEncodedCert(const net::ParsedCertificate* cert,
                       std::vector<std::string>* pem_encoded_chain) {
  std::string der_cert;
  cert->der_cert().AsStringPiece().CopyToString(&der_cert);
  std::string pem;
  if (!net::X509Certificate::GetPEMEncodedFromDER(der_cert, &pem)) {
    std::cerr << "ERROR: GetPEMEncodedFromDER failed\n";
    return false;
  }
  pem_encoded_chain->push_back(pem);
  return true;
}

// Dumps a chain of ParsedCertificate objects to a PEM file.
bool DumpParsedCertificateChain(const base::FilePath& file_path,
                                const net::CertPath& chain) {
  std::vector<std::string> pem_encoded_chain;
  for (const auto& cert : chain.certs) {
    if (!AddPemEncodedCert(cert.get(), &pem_encoded_chain))
      return false;
  }

  if (chain.trust_anchor && chain.trust_anchor->cert()) {
    if (!AddPemEncodedCert(chain.trust_anchor->cert().get(),
                           &pem_encoded_chain))
      return false;
  }

  return WriteToFile(file_path, base::JoinString(pem_encoded_chain, ""));
}

// Returns a hex-encoded sha256 of the DER-encoding of |cert|.
std::string FingerPrintParsedCertificate(const net::ParsedCertificate* cert) {
  std::string hash = crypto::SHA256HashString(cert->der_cert().AsStringPiece());
  return base::HexEncode(hash.data(), hash.size());
}

std::string SubjectToString(const net::RDNSequence& parsed_subject) {
  std::string subject_str;
  if (!net::ConvertToRFC2253(parsed_subject, &subject_str))
    return std::string();
  return subject_str;
}

// Returns a textual representation of the Subject of |cert|.
std::string SubjectFromParsedCertificate(const net::ParsedCertificate* cert) {
  net::RDNSequence parsed_subject;
  if (!net::ParseName(cert->tbs().subject_tlv, &parsed_subject))
    return std::string();
  return SubjectToString(parsed_subject);
}

// Returns a textual representation of the Subject of |trust_anchor|.
std::string SubjectFromTrustAnchor(const net::TrustAnchor* trust_anchor) {
  // If the cert is present, display the original subject from that rather than
  // the normalized subject.
  if (trust_anchor->cert())
    return SubjectFromParsedCertificate(trust_anchor->cert().get());

  net::RDNSequence parsed_subject;
  if (!net::ParseNameValue(trust_anchor->normalized_subject(), &parsed_subject))
    return std::string();
  return SubjectToString(parsed_subject);
}

// Dumps a ResultPath to std::cout.
void PrintResultPath(const net::CertPathBuilder::ResultPath* result_path,
                     size_t index,
                     bool is_best) {
  std::cout << "path " << index << " "
            << (result_path->valid ? "valid" : "invalid")
            << (is_best ? " (best)" : "") << "\n";

  // Print the certificate chain.
  for (const auto& cert : result_path->path.certs) {
    std::cout << " " << FingerPrintParsedCertificate(cert.get()) << " "
              << SubjectFromParsedCertificate(cert.get()) << "\n";
  }

  // Print the trust anchor (if there was one).
  const auto& trust_anchor = result_path->path.trust_anchor;
  if (trust_anchor) {
    std::string trust_anchor_cert_fingerprint = "<no cert>";
    if (trust_anchor->cert()) {
      trust_anchor_cert_fingerprint =
          FingerPrintParsedCertificate(trust_anchor->cert().get());
    }
    std::cout << " " << trust_anchor_cert_fingerprint << " "
              << SubjectFromTrustAnchor(trust_anchor.get()) << "\n";
  }

  // Print the errors.
  if (!result_path->errors.empty()) {
    std::cout << "Errors:\n";
    std::cout << result_path->errors.ToDebugString() << "\n";
  }
}

scoped_refptr<net::ParsedCertificate> ParseCertificate(const CertInput& input) {
  net::CertErrors errors;
  scoped_refptr<net::ParsedCertificate> cert = net::ParsedCertificate::Create(
      net::x509_util::CreateCryptoBuffer(input.der_cert), {}, &errors);
  if (!cert) {
    PrintCertError("ERROR: ParsedCertificate failed:", input);
    std::cout << errors.ToDebugString() << "\n";
  }

  // TODO(crbug.com/634443): Print errors if there are any on success too (i.e.
  //                         warnings).

  return cert;
}

void SetUpOnNetworkThread(std::unique_ptr<net::URLRequestContext>* context,
                          scoped_refptr<net::CertNetFetcher>* fetcher,
                          base::WaitableEvent* initialization_complete_event) {
  // TODO(mattm): add command line flags to configure using
  // CertIssuerSourceAia
  // (similar to VERIFY_CERT_IO_ENABLED flag for CertVerifyProc).
  net::URLRequestContextBuilder url_request_context_builder;
  url_request_context_builder.set_user_agent(GetUserAgent());
#if defined(OS_LINUX)
  // On Linux, use a fixed ProxyConfigService, since the default one
  // depends on glib.
  //
  // TODO(akalin): Remove this once http://crbug.com/146421 is fixed.
  url_request_context_builder.set_proxy_config_service(
      base::MakeUnique<net::ProxyConfigServiceFixed>(net::ProxyConfig()));
#endif
  *context = url_request_context_builder.Build();

  *fetcher = net::CreateCertNetFetcher(context->get());
  initialization_complete_event->Signal();
}

void ShutdownOnNetworkThread(
    std::unique_ptr<net::URLRequestContext>* context,
    const scoped_refptr<net::CertNetFetcher>& cert_net_fetcher) {
  cert_net_fetcher->Shutdown();
  context->reset();
}

}  // namespace

// Verifies |target_der_cert| using CertPathBuilder.
bool VerifyUsingPathBuilder(
    const CertInput& target_der_cert,
    const std::vector<CertInput>& intermediate_der_certs,
    const std::vector<CertInput>& root_der_certs,
    const base::Time at_time,
    const base::FilePath& dump_prefix_path) {
  base::Time::Exploded exploded_time;
  at_time.UTCExplode(&exploded_time);
  net::der::GeneralizedTime time = ConvertExplodedTime(exploded_time);

  net::TrustStoreCollection trust_store;

  net::TrustStoreInMemory trust_store_in_memory;
  trust_store.AddTrustStore(&trust_store_in_memory);
  for (const auto& der_cert : root_der_certs) {
    scoped_refptr<net::ParsedCertificate> cert = ParseCertificate(der_cert);
    if (cert) {
      trust_store_in_memory.AddTrustAnchor(
          net::TrustAnchor::CreateFromCertificateNoConstraints(cert));
    }
  }

#if defined(USE_NSS_CERTS)
  net::TrustStoreNSS trust_store_nss(trustSSL);
  trust_store.AddTrustStore(&trust_store_nss);
#elif defined(OS_MACOSX) && !defined(OS_IOS)
  net::TrustStoreMac trust_store_mac(kSecPolicyAppleSSL);
  trust_store.AddTrustStore(&trust_store_mac);
#else
  if (root_der_certs.empty()) {
    std::cerr << "NOTE: CertPathBuilder does not currently use OS trust "
                 "settings (--roots must be specified).\n";
  }
#endif

  net::CertIssuerSourceStatic intermediate_cert_issuer_source;
  for (const auto& der_cert : intermediate_der_certs) {
    scoped_refptr<net::ParsedCertificate> cert = ParseCertificate(der_cert);
    if (cert)
      intermediate_cert_issuer_source.AddCert(cert);
  }

  scoped_refptr<net::ParsedCertificate> target_cert =
      ParseCertificate(target_der_cert);
  if (!target_cert)
    return false;

  // Verify the chain.
  net::SimpleSignaturePolicy signature_policy(2048);
  net::CertPathBuilder::Result result;
  net::CertPathBuilder path_builder(target_cert, &trust_store,
                                    &signature_policy, time, &result);
  path_builder.AddCertIssuerSource(&intermediate_cert_issuer_source);
#if defined(USE_NSS_CERTS)
  net::CertIssuerSourceNSS cert_issuer_source_nss;
  path_builder.AddCertIssuerSource(&cert_issuer_source_nss);
#endif

  // Create a network thread to be used for AIA fetches, and wait for a
  // CertNetFetcher to be constructed on that thread.
  base::Thread::Options options(base::MessageLoop::TYPE_IO, 0);
  base::Thread thread("network_thread");
  CHECK(thread.StartWithOptions(options));
  // Owned by this thread, but initialized, used, and shutdown on the network
  // thread.
  std::unique_ptr<net::URLRequestContext> context;
  scoped_refptr<net::CertNetFetcher> cert_net_fetcher;
  base::WaitableEvent initialization_complete_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  thread.task_runner()->PostTask(
      FROM_HERE, base::Bind(&SetUpOnNetworkThread, &context, &cert_net_fetcher,
                            &initialization_complete_event));
  initialization_complete_event.Wait();

  // Now that the CertNetFetcher has been created on the network thread,
  // use it to create a CertIssuerSourceAia.
  net::CertIssuerSourceAia aia_cert_issuer_source(cert_net_fetcher.get());
  path_builder.AddCertIssuerSource(&aia_cert_issuer_source);

  // Run the path builder.
  path_builder.Run();

  // Clean up on the network thread and stop it (which waits for the clean up
  // task to run).
  thread.task_runner()->PostTask(
      FROM_HERE,
      base::Bind(&ShutdownOnNetworkThread, &context, cert_net_fetcher));
  thread.Stop();

  // TODO(crbug.com/634443): Display any errors/warnings associated with path
  //                         building that were not part of a particular
  //                         PathResult.
  std::cout << "CertPathBuilder result: "
            << (result.HasValidPath() ? "SUCCESS" : "FAILURE") << "\n";

  for (size_t i = 0; i < result.paths.size(); ++i) {
    PrintResultPath(result.paths[i].get(), i, i == result.best_result_index);
  }

  // TODO(mattm): add flag to dump all paths, not just the final one?
  if (!dump_prefix_path.empty() && result.paths.size()) {
    if (!DumpParsedCertificateChain(
            dump_prefix_path.AddExtension(
                FILE_PATH_LITERAL(".CertPathBuilder.pem")),
            result.paths[result.best_result_index]->path)) {
      return false;
    }
  }

  return result.HasValidPath();
}
