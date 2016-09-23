// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "base/macros.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/certificate_policies.h"
#include "net/cert/internal/extended_key_usage.h"
#include "net/cert/internal/name_constraints.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/parse_name.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/verify_signed_data.h"

namespace net {
namespace {

bool FindExtension(const der::Input& oid,
                   std::map<der::Input, ParsedExtension>* extensions,
                   ParsedExtension* extension) {
  auto it = extensions->find(oid);
  if (it == extensions->end())
    return false;
  *extension = it->second;
  return true;
}

void ParseCertificateForFuzzer(const der::Input& in) {
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  CertErrors errors;
  if (!ParseCertificate(in, &tbs_certificate_tlv, &signature_algorithm_tlv,
                        &signature_value, &errors))
    return;
  std::unique_ptr<SignatureAlgorithm> sig_alg(
      SignatureAlgorithm::Create(signature_algorithm_tlv, &errors));

  ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv, {}, &tbs, &errors))
    return;

  RDNSequence subject;
  ignore_result(ParseName(tbs.subject_tlv, &subject));

  std::map<der::Input, ParsedExtension> extensions;
  if (tbs.has_extensions && ParseExtensions(tbs.extensions_tlv, &extensions)) {
    ParsedExtension extension;
    ParsedBasicConstraints basic_constraints;
    der::BitString key_usage;
    std::vector<der::Input> policies;
    std::vector<der::Input> eku_oids;
    std::vector<base::StringPiece> ca_issuers_uris;
    std::vector<base::StringPiece> ocsp_uris;
    if (FindExtension(BasicConstraintsOid(), &extensions, &extension))
      ignore_result(ParseBasicConstraints(extension.value, &basic_constraints));
    if (FindExtension(KeyUsageOid(), &extensions, &extension))
      ignore_result(ParseKeyUsage(extension.value, &key_usage));
    if (FindExtension(SubjectAltNameOid(), &extensions, &extension))
      GeneralNames::CreateFromDer(extension.value);
    if (FindExtension(CertificatePoliciesOid(), &extensions, &extension))
      ParseCertificatePoliciesExtension(extension.value, &policies);
    if (FindExtension(ExtKeyUsageOid(), &extensions, &extension))
      ParseEKUExtension(extension.value, &eku_oids);
    if (FindExtension(AuthorityInfoAccessOid(), &extensions, &extension))
      ignore_result(ParseAuthorityInfoAccess(extension.value, &ca_issuers_uris,
                                             &ocsp_uris));
  }
}

}  // namespace
}  // namespace net

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::der::Input in(data, size);
  net::ParseCertificateForFuzzer(in);
  return 0;
}
