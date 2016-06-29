// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/parse_ocsp.h"

#include "base/files/file_path.h"
#include "base/logging.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/x509_certificate.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

std::string GetFilePath(const std::string& file_name) {
  return std::string("net/data/parse_ocsp_unittest/") + file_name;
}

enum OCSPFailure {
  OCSP_SUCCESS,
  PARSE_CERT,
  PARSE_OCSP,
  OCSP_NOT_SUCCESSFUL,
  PARSE_OCSP_DATA,
  PARSE_OCSP_SINGLE_RESPONSE,
  VERIFY_OCSP,
  OCSP_SUCCESS_REVOKED,
  OCSP_SUCCESS_UNKNOWN,
};

OCSPFailure ParseOCSP(const std::string& file_name) {
  std::string ocsp_data;
  std::string ca_data;
  std::string cert_data;
  const PemBlockMapping mappings[] = {
      {"OCSP RESPONSE", &ocsp_data},
      {"CA CERTIFICATE", &ca_data},
      {"CERTIFICATE", &cert_data},
  };

  if (!ReadTestDataFromPemFile(GetFilePath(file_name), mappings))
    return PARSE_CERT;

  der::Input ocsp_input(&ocsp_data);
  der::Input ca_input(&ca_data);
  der::Input cert_input(&cert_data);

  der::Input issuer_tbs_certificate_tlv;
  der::Input issuer_signature_algorithm_tlv;
  der::BitString issuer_signature_value;
  der::Input cert_tbs_certificate_tlv;
  der::Input cert_signature_algorithm_tlv;
  der::BitString cert_signature_value;
  if (!ParseCertificate(ca_input, &issuer_tbs_certificate_tlv,
                        &issuer_signature_algorithm_tlv,
                        &issuer_signature_value))
    return PARSE_CERT;
  if (!ParseCertificate(cert_input, &cert_tbs_certificate_tlv,
                        &cert_signature_algorithm_tlv, &cert_signature_value))
    return PARSE_CERT;
  OCSPResponse parsed_ocsp;
  OCSPResponseData parsed_ocsp_data;
  if (!ParseOCSPResponse(ocsp_input, &parsed_ocsp))
    return PARSE_OCSP;
  if (parsed_ocsp.status != OCSPResponse::ResponseStatus::SUCCESSFUL)
    return OCSP_NOT_SUCCESSFUL;
  if (!ParseOCSPResponseData(parsed_ocsp.data, &parsed_ocsp_data))
    return PARSE_OCSP_DATA;

  OCSPCertStatus status;

  if (!GetOCSPCertStatus(parsed_ocsp_data, issuer_tbs_certificate_tlv,
                         cert_tbs_certificate_tlv, &status))
    return PARSE_OCSP_SINGLE_RESPONSE;

  switch (status.status) {
    case OCSPCertStatus::Status::GOOD:
      return OCSP_SUCCESS;
    case OCSPCertStatus::Status::REVOKED:
      return OCSP_SUCCESS_REVOKED;
    case OCSPCertStatus::Status::UNKNOWN:
      return OCSP_SUCCESS_UNKNOWN;
  }

  return OCSP_SUCCESS_UNKNOWN;
}

}  // namespace

TEST(ParseOCSPTest, OCSPGoodResponse) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("good_response.pem"));
}

TEST(ParseOCSPTest, OCSPNoResponse) {
  ASSERT_EQ(PARSE_OCSP_SINGLE_RESPONSE, ParseOCSP("no_response.pem"));
}

TEST(ParseOCSPTest, OCSPMalformedStatus) {
  ASSERT_EQ(OCSP_NOT_SUCCESSFUL, ParseOCSP("malformed_status.pem"));
}

TEST(ParseOCSPTest, OCSPBadStatus) {
  ASSERT_EQ(PARSE_OCSP, ParseOCSP("bad_status.pem"));
}

TEST(ParseOCSPTest, OCSPInvalidOCSPOid) {
  ASSERT_EQ(PARSE_OCSP, ParseOCSP("bad_ocsp_type.pem"));
}

TEST(ParseOCSPTest, OCSPBadSignature) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("bad_signature.pem"));
}

TEST(ParseOCSPTest, OCSPDirectSignature) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("ocsp_sign_direct.pem"));
}

TEST(ParseOCSPTest, OCSPIndirectSignature) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("ocsp_sign_indirect.pem"));
}

TEST(ParseOCSPTest, OCSPMissingIndirectSignature) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("ocsp_sign_indirect_missing.pem"));
}

TEST(ParseOCSPTest, OCSPInvalidSignature) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("ocsp_sign_bad_indirect.pem"));
}

TEST(ParseOCSPTest, OCSPExtraCerts) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("ocsp_extra_certs.pem"));
}

TEST(ParseOCSPTest, OCSPIncludesVersion) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("has_version.pem"));
}

TEST(ParseOCSPTest, OCSPResponderName) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("responder_name.pem"));
}

TEST(ParseOCSPTest, OCSPResponderKeyHash) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("responder_id.pem"));
}

TEST(ParseOCSPTest, OCSPOCSPExtension) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("has_extension.pem"));
}

TEST(ParseOCSPTest, OCSPIncludeNextUpdate) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("good_response_next_update.pem"));
}

TEST(ParseOCSPTest, OCSPRevokedResponse) {
  ASSERT_EQ(OCSP_SUCCESS_REVOKED, ParseOCSP("revoke_response.pem"));
}

TEST(ParseOCSPTest, OCSPRevokedResponseWithReason) {
  ASSERT_EQ(OCSP_SUCCESS_REVOKED, ParseOCSP("revoke_response_reason.pem"));
}

TEST(ParseOCSPTest, OCSPUnknownCertStatus) {
  ASSERT_EQ(OCSP_SUCCESS_UNKNOWN, ParseOCSP("unknown_response.pem"));
}

TEST(ParseOCSPTest, OCSPMultipleCertStatus) {
  ASSERT_EQ(OCSP_SUCCESS_UNKNOWN, ParseOCSP("multiple_response.pem"));
}

TEST(ParseOCSPTest, OCSPWrongCertResponse) {
  ASSERT_EQ(PARSE_OCSP_SINGLE_RESPONSE, ParseOCSP("other_response.pem"));
}

TEST(ParseOCSPTest, OCSPOCSPSingleExtension) {
  ASSERT_EQ(OCSP_SUCCESS, ParseOCSP("has_single_extension.pem"));
}

TEST(ParseOCSPTest, OCSPMissingResponse) {
  ASSERT_EQ(PARSE_OCSP_SINGLE_RESPONSE, ParseOCSP("missing_response.pem"));
}

}  // namespace net
