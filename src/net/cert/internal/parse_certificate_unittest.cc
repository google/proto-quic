// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/parse_certificate.h"

#include "base/strings/stringprintf.h"
#include "net/cert/internal/test_helpers.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Pretty-prints a GeneralizedTime as a human-readable string for use in test
// expectations (it is more readable to specify the expected results as a
// string).
std::string ToString(const der::GeneralizedTime& time) {
  return base::StringPrintf(
      "year=%d, month=%d, day=%d, hours=%d, minutes=%d, seconds=%d", time.year,
      time.month, time.day, time.hours, time.minutes, time.seconds);
}

std::string GetFilePath(const std::string& file_name) {
  return std::string("net/data/parse_certificate_unittest/") + file_name;
}

// Loads certificate data and expectations from the PEM file |file_name|.
// Verifies that parsing the Certificate succeeds, and each parsed field matches
// the expectations.
void EnsureParsingCertificateSucceeds(const std::string& file_name) {
  std::string data;
  std::string expected_tbs_certificate;
  std::string expected_signature_algorithm;
  std::string expected_signature;

  // Read the certificate data and test expectations from a single PEM file.
  const PemBlockMapping mappings[] = {
      {"CERTIFICATE", &data},
      {"SIGNATURE", &expected_signature},
      {"SIGNATURE ALGORITHM", &expected_signature_algorithm},
      {"TBS CERTIFICATE", &expected_tbs_certificate},
  };
  ASSERT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));

  // Parsing the certificate should succeed.
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  ASSERT_TRUE(ParseCertificate(der::Input(&data), &tbs_certificate_tlv,
                               &signature_algorithm_tlv, &signature_value));

  // Ensure that the parsed certificate matches expectations.
  EXPECT_EQ(0, signature_value.unused_bits());
  EXPECT_EQ(der::Input(&expected_signature), signature_value.bytes());
  EXPECT_EQ(der::Input(&expected_signature_algorithm), signature_algorithm_tlv);
  EXPECT_EQ(der::Input(&expected_tbs_certificate), tbs_certificate_tlv);
}

// Loads certificate data from the PEM file |file_name| and verifies that the
// Certificate parsing fails.
void EnsureParsingCertificateFails(const std::string& file_name) {
  std::string data;

  const PemBlockMapping mappings[] = {
      {"CERTIFICATE", &data},
  };

  ASSERT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));

  // Parsing the Certificate should fail.
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  ASSERT_FALSE(ParseCertificate(der::Input(&data), &tbs_certificate_tlv,
                                &signature_algorithm_tlv, &signature_value));
}

// Tests parsing a Certificate.
TEST(ParseCertificateTest, Version3) {
  EnsureParsingCertificateSucceeds("cert_version3.pem");
}

// Tests parsing a simplified Certificate-like structure (the sub-fields for
// algorithm and tbsCertificate are not actually valid, but ParseCertificate()
// doesn't check them)
TEST(ParseCertificateTest, Skeleton) {
  EnsureParsingCertificateSucceeds("cert_skeleton.pem");
}

// Tests parsing a Certificate that is not a sequence fails.
TEST(ParseCertificateTest, NotSequence) {
  EnsureParsingCertificateFails("cert_not_sequence.pem");
}

// Tests that uncomsumed data is not allowed after the main SEQUENCE.
TEST(ParseCertificateTest, DataAfterSignature) {
  EnsureParsingCertificateFails("cert_data_after_signature.pem");
}

// Tests that parsing fails if the signature BIT STRING is missing.
TEST(ParseCertificateTest, MissingSignature) {
  EnsureParsingCertificateFails("cert_missing_signature.pem");
}

// Tests that parsing fails if the signature is present but not a BIT STRING.
TEST(ParseCertificateTest, SignatureNotBitString) {
  EnsureParsingCertificateFails("cert_signature_not_bit_string.pem");
}

// Tests that parsing fails if the main SEQUENCE is empty (missing all the
// fields).
TEST(ParseCertificateTest, EmptySequence) {
  EnsureParsingCertificateFails("cert_empty_sequence.pem");
}

// Tests what happens when the signature algorithm is present, but has the wrong
// tag.
TEST(ParseCertificateTest, AlgorithmNotSequence) {
  EnsureParsingCertificateFails("cert_algorithm_not_sequence.pem");
}

// Loads tbsCertificate data and expectations from the PEM file |file_name|.
// Verifies that parsing the TBSCertificate succeeds, and each parsed field
// matches the expectations.
void EnsureParsingTbsSucceeds(const std::string& file_name,
                              CertificateVersion expected_version) {
  std::string data;
  std::string expected_serial_number;
  std::string expected_signature_algorithm;
  std::string expected_issuer;
  std::string expected_validity_not_before;
  std::string expected_validity_not_after;
  std::string expected_subject;
  std::string expected_spki;
  std::string expected_issuer_unique_id;
  std::string expected_subject_unique_id;
  std::string expected_extensions;

  // Read the certificate data and test expectations from a single PEM file.
  const PemBlockMapping mappings[] = {
      {"TBS CERTIFICATE", &data},
      {"SIGNATURE ALGORITHM", &expected_signature_algorithm},
      {"SERIAL NUMBER", &expected_serial_number},
      {"ISSUER", &expected_issuer},
      {"VALIDITY NOTBEFORE", &expected_validity_not_before},
      {"VALIDITY NOTAFTER", &expected_validity_not_after},
      {"SUBJECT", &expected_subject},
      {"SPKI", &expected_spki},
      {"ISSUER UNIQUE ID", &expected_issuer_unique_id, true},
      {"SUBJECT UNIQUE ID", &expected_subject_unique_id, true},
      {"EXTENSIONS", &expected_extensions, true},
  };
  ASSERT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));

  // Parsing the TBSCertificate should succeed.
  ParsedTbsCertificate parsed;
  ASSERT_TRUE(ParseTbsCertificate(der::Input(&data), {}, &parsed));

  // Ensure that the ParsedTbsCertificate matches expectations.
  EXPECT_EQ(expected_version, parsed.version);

  EXPECT_EQ(der::Input(&expected_serial_number), parsed.serial_number);
  EXPECT_EQ(der::Input(&expected_signature_algorithm),
            parsed.signature_algorithm_tlv);

  EXPECT_EQ(der::Input(&expected_issuer), parsed.issuer_tlv);

  // In the test expectations PEM file, validity is described as a
  // textual string of the parsed value (rather than as DER).
  EXPECT_EQ(expected_validity_not_before, ToString(parsed.validity_not_before));
  EXPECT_EQ(expected_validity_not_after, ToString(parsed.validity_not_after));

  EXPECT_EQ(der::Input(&expected_subject), parsed.subject_tlv);
  EXPECT_EQ(der::Input(&expected_spki), parsed.spki_tlv);

  EXPECT_EQ(der::Input(&expected_issuer_unique_id),
            parsed.issuer_unique_id.bytes());
  EXPECT_EQ(!expected_issuer_unique_id.empty(), parsed.has_issuer_unique_id);
  EXPECT_EQ(der::Input(&expected_subject_unique_id),
            parsed.subject_unique_id.bytes());
  EXPECT_EQ(!expected_subject_unique_id.empty(), parsed.has_subject_unique_id);

  EXPECT_EQ(der::Input(&expected_extensions), parsed.extensions_tlv);
  EXPECT_EQ(!expected_extensions.empty(), parsed.has_extensions);
}

// Loads certificate data from the PEM file |file_name| and verifies that the
// Certificate parsing succeed, however the TBSCertificate parsing fails.
void EnsureParsingTbsFails(const std::string& file_name) {
  std::string data;

  const PemBlockMapping mappings[] = {
      {"TBS CERTIFICATE", &data},
  };

  ASSERT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));

  // Parsing the TBSCertificate should fail.
  ParsedTbsCertificate parsed;
  ASSERT_FALSE(ParseTbsCertificate(der::Input(&data), {}, &parsed));
}

// Tests parsing a TBSCertificate for v3 that contains no optional fields.
TEST(ParseTbsCertificateTest, Version3NoOptionals) {
  EnsureParsingTbsSucceeds("tbs_v3_no_optionals.pem", CertificateVersion::V3);
}

// Tests parsing a TBSCertificate for v3 that contains extensions.
TEST(ParseTbsCertificateTest, Version3WithExtensions) {
  EnsureParsingTbsSucceeds("tbs_v3_extensions.pem", CertificateVersion::V3);
}

// Tests parsing a TBSCertificate for v3 that contains no optional fields, and
// has a negative serial number.
//
// CAs are not supposed to include negative serial numbers, however RFC 5280
// expects consumers to deal with it anyway).
TEST(ParseTbsCertificateTest, NegativeSerialNumber) {
  EnsureParsingTbsSucceeds("tbs_negative_serial_number.pem",
                           CertificateVersion::V3);
}

// Tests parsing a TBSCertificate with a serial number that is 21 octets long
// (and the first byte is 0).
TEST(ParseTbCertificateTest, SerialNumber21OctetsLeading0) {
  EnsureParsingTbsFails("tbs_serial_number_21_octets_leading_0.pem");
}

// Tests parsing a TBSCertificate with a serial number that is 26 octets long
// (and does not contain a leading 0).
TEST(ParseTbsCertificateTest, SerialNumber26Octets) {
  EnsureParsingTbsFails("tbs_serial_number_26_octets.pem");
}

// Tests parsing a TBSCertificate which lacks a version number (causing it to
// default to v1).
TEST(ParseTbsCertificateTest, Version1) {
  EnsureParsingTbsSucceeds("tbs_v1.pem", CertificateVersion::V1);
}

// The version was set to v1 explicitly rather than omitting the version field.
TEST(ParseTbsCertificateTest, ExplicitVersion1) {
  EnsureParsingTbsFails("tbs_explicit_v1.pem");
}

// Extensions are not defined in version 1.
TEST(ParseTbsCertificateTest, Version1WithExtensions) {
  EnsureParsingTbsFails("tbs_v1_extensions.pem");
}

// Extensions are not defined in version 2.
TEST(ParseTbsCertificateTest, Version2WithExtensions) {
  EnsureParsingTbsFails("tbs_v2_extensions.pem");
}

// A boring version 2 certificate with none of the optional fields.
TEST(ParseTbsCertificateTest, Version2NoOptionals) {
  EnsureParsingTbsSucceeds("tbs_v2_no_optionals.pem", CertificateVersion::V2);
}

// A version 2 certificate with an issuer unique ID field.
TEST(ParseTbsCertificateTest, Version2IssuerUniqueId) {
  EnsureParsingTbsSucceeds("tbs_v2_issuer_unique_id.pem",
                           CertificateVersion::V2);
}

// A version 2 certificate with both a issuer and subject unique ID field.
TEST(ParseTbsCertificateTest, Version2IssuerAndSubjectUniqueId) {
  EnsureParsingTbsSucceeds("tbs_v2_issuer_and_subject_unique_id.pem",
                           CertificateVersion::V2);
}

// A version 3 certificate with all of the optional fields (issuer unique id,
// subject unique id, and extensions).
TEST(ParseTbsCertificateTest, Version3AllOptionals) {
  EnsureParsingTbsSucceeds("tbs_v3_all_optionals.pem", CertificateVersion::V3);
}

// The version was set to v4, which is unrecognized.
TEST(ParseTbsCertificateTest, Version4) {
  EnsureParsingTbsFails("tbs_v4.pem");
}

// Tests that extraneous data after extensions in a v3 is rejected.
TEST(ParseTbsCertificateTest, Version3DataAfterExtensions) {
  EnsureParsingTbsFails("tbs_v3_data_after_extensions.pem");
}

// Tests using a real-world certificate (whereas the other tests are fabricated
// (and in fact invalid) data.
TEST(ParseTbsCertificateTest, Version3Real) {
  EnsureParsingTbsSucceeds("tbs_v3_real.pem", CertificateVersion::V3);
}

// Parses a TBSCertificate whose "validity" field expresses both notBefore
// and notAfter using UTCTime.
TEST(ParseTbsCertificateTest, ValidityBothUtcTime) {
  EnsureParsingTbsSucceeds("tbs_validity_both_utc_time.pem",
                           CertificateVersion::V3);
}

// Parses a TBSCertificate whose "validity" field expresses both notBefore
// and notAfter using GeneralizedTime.
TEST(ParseTbsCertificateTest, ValidityBothGeneralizedTime) {
  EnsureParsingTbsSucceeds("tbs_validity_both_generalized_time.pem",
                           CertificateVersion::V3);
}

// Parses a TBSCertificate whose "validity" field expresses notBefore using
// UTCTime and notAfter using GeneralizedTime.
TEST(ParseTbsCertificateTest, ValidityUTCTimeAndGeneralizedTime) {
  EnsureParsingTbsSucceeds("tbs_validity_utc_time_and_generalized_time.pem",
                           CertificateVersion::V3);
}

// Parses a TBSCertificate whose validity" field expresses notBefore using
// GeneralizedTime and notAfter using UTCTime. Also of interest, notBefore >
// notAfter. Parsing will succeed, however no time can satisfy this constraint.
TEST(ParseTbsCertificateTest, ValidityGeneralizedTimeAndUTCTime) {
  EnsureParsingTbsSucceeds("tbs_validity_generalized_time_and_utc_time.pem",
                           CertificateVersion::V3);
}

// Parses a TBSCertificate whose "validity" field does not strictly follow
// the DER rules (and fails to be parsed).
TEST(ParseTbsCertificateTest, ValidityRelaxed) {
  EnsureParsingTbsFails("tbs_validity_relaxed.pem");
}

// Reads a PEM file containing a block "EXTENSION". This input will be
// passed to ParseExtension, and the results filled in |out|.
bool ParseExtensionFromFile(const std::string& file_name,
                            ParsedExtension* out,
                            std::string* data) {
  const PemBlockMapping mappings[] = {
      {"EXTENSION", data},
  };

  EXPECT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));
  return ParseExtension(der::Input(data), out);
}

// Parses an Extension whose critical field is true (255).
TEST(ParseExtensionTest, Critical) {
  std::string data;
  ParsedExtension extension;
  ASSERT_TRUE(
      ParseExtensionFromFile("extension_critical.pem", &extension, &data));

  EXPECT_TRUE(extension.critical);

  const uint8_t kExpectedOid[] = {0x55, 0x1d, 0x13};
  EXPECT_EQ(der::Input(kExpectedOid), extension.oid);

  const uint8_t kExpectedValue[] = {0x30, 0x00};
  EXPECT_EQ(der::Input(kExpectedValue), extension.value);
}

// Parses an Extension whose critical field is false (omitted).
TEST(ParseExtensionTest, NotCritical) {
  std::string data;
  ParsedExtension extension;
  ASSERT_TRUE(
      ParseExtensionFromFile("extension_not_critical.pem", &extension, &data));

  EXPECT_FALSE(extension.critical);

  const uint8_t kExpectedOid[] = {0x55, 0x1d, 0x13};
  EXPECT_EQ(der::Input(kExpectedOid), extension.oid);

  const uint8_t kExpectedValue[] = {0x30, 0x00};
  EXPECT_EQ(der::Input(kExpectedValue), extension.value);
}

// Parses an Extension whose critical field is 0. This is in one sense FALSE,
// however because critical has DEFAULT of false this is in fact invalid
// DER-encoding.
TEST(ParseExtensionTest, Critical0) {
  std::string data;
  ParsedExtension extension;
  ASSERT_FALSE(
      ParseExtensionFromFile("extension_critical_0.pem", &extension, &data));
}

// Parses an Extension whose critical field is 3. Under DER-encoding BOOLEAN
// values must an octet of either all zero bits, or all 1 bits, so this is not
// valid.
TEST(ParseExtensionTest, Critical3) {
  std::string data;
  ParsedExtension extension;
  ASSERT_FALSE(
      ParseExtensionFromFile("extension_critical_3.pem", &extension, &data));
}

// Runs a test for extensions parsing. The input file is a PEM file which
// contains a DER-encoded Extensions sequence, as well as the expected value
// for each contained extension.
void EnsureParsingExtensionsSucceeds(
    const std::string& file_name,
    std::map<der::Input, ParsedExtension>* extensions,
    std::string* data) {
  const PemBlockMapping mappings[] = {
      // Test Input.
      {"EXTENSIONS", data},
  };

  ASSERT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));
  ASSERT_TRUE(ParseExtensions(der::Input(data), extensions));
}

// Runs a test that verifies extensions parsing fails. The input file is a PEM
// file which contains a DER-encoded Extensions sequence.
void EnsureParsingExtensionsFails(const std::string& file_name) {
  std::string data;

  const PemBlockMapping mappings[] = {
      {"EXTENSIONS", &data},
  };

  std::map<der::Input, ParsedExtension> extensions;
  ASSERT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));
  ASSERT_FALSE(ParseExtensions(der::Input(&data), &extensions));
}

// Parses an Extensions that is an empty sequence.
TEST(ParseExtensionsTest, EmptySequence) {
  EnsureParsingExtensionsFails("extensions_empty_sequence.pem");
}

// Parses an Extensions that is not a sequence.
TEST(ParseExtensionsTest, NotSequence) {
  EnsureParsingExtensionsFails("extensions_not_sequence.pem");
}

// Parses an Extensions that has data after the sequence.
TEST(ParseExtensionsTest, DataAfterSequence) {
  EnsureParsingExtensionsFails("extensions_data_after_sequence.pem");
}

// Parses an Extensions that contains duplicated key usages.
TEST(ParseExtensionsTest, DuplicateKeyUsage) {
  EnsureParsingExtensionsFails("extensions_duplicate_key_usage.pem");
}

// Parses an Extensions that contains an unknown critical extension.
TEST(ParseExtensionsTest, UnknownCritical) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_unknown_critical.pem",
                                  &extensions, &data);

  ASSERT_EQ(1u, extensions.size());
  // This OID corresponds with
  // 1.2.840.113554.4.1.72585.0 (https://davidben.net/oid)
  const uint8_t oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12,
                         0x04, 0x01, 0x84, 0xb7, 0x09, 0x00};

  auto iter = extensions.find(der::Input(oid));
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_TRUE(iter->second.critical);
  EXPECT_EQ(4u, iter->second.value.Length());
}

// Parses an Extensions that contains an unknown non-critical extension.
TEST(ParseExtensionsTest, UnknownNonCritical) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_unknown_non_critical.pem",
                                  &extensions, &data);

  ASSERT_EQ(1u, extensions.size());
  // This OID corresponds with
  // 1.2.840.113554.4.1.72585.0 (https://davidben.net/oid)
  const uint8_t oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12,
                         0x04, 0x01, 0x84, 0xb7, 0x09, 0x00};

  auto iter = extensions.find(der::Input(oid));
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_FALSE(iter->second.critical);
  EXPECT_EQ(4u, iter->second.value.Length());
}

// Parses an Extensions that contains a basic constraints.
TEST(ParseExtensionsTest, BasicConstraints) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_basic_constraints.pem",
                                  &extensions, &data);

  ASSERT_EQ(1u, extensions.size());

  auto iter = extensions.find(BasicConstraintsOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_TRUE(iter->second.critical);
  EXPECT_EQ(2u, iter->second.value.Length());
}

// Parses an Extensions that contains an extended key usages.
TEST(ParseExtensionsTest, ExtendedKeyUsage) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_extended_key_usage.pem",
                                  &extensions, &data);

  ASSERT_EQ(1u, extensions.size());

  auto iter = extensions.find(ExtKeyUsageOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_FALSE(iter->second.critical);
  EXPECT_EQ(45u, iter->second.value.Length());
}

// Parses an Extensions that contains a key usage.
TEST(ParseExtensionsTest, KeyUsage) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_key_usage.pem", &extensions,
                                  &data);

  ASSERT_EQ(1u, extensions.size());

  auto iter = extensions.find(KeyUsageOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_TRUE(iter->second.critical);
  EXPECT_EQ(4u, iter->second.value.Length());
}

// Parses an Extensions that contains a policies extension.
TEST(ParseExtensionsTest, Policies) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_policies.pem", &extensions,
                                  &data);

  ASSERT_EQ(1u, extensions.size());

  auto iter = extensions.find(CertificatePoliciesOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_FALSE(iter->second.critical);
  EXPECT_EQ(95u, iter->second.value.Length());
}

// Parses an Extensions that contains a subjectaltname extension.
TEST(ParseExtensionsTest, SubjectAltName) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_subject_alt_name.pem",
                                  &extensions, &data);

  ASSERT_EQ(1u, extensions.size());

  auto iter = extensions.find(SubjectAltNameOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_FALSE(iter->second.critical);
  EXPECT_EQ(23u, iter->second.value.Length());
}

// Parses an Extensions that contains multiple extensions, sourced from a
// real-world certificate.
TEST(ParseExtensionsTest, Real) {
  std::string data;
  std::map<der::Input, ParsedExtension> extensions;
  EnsureParsingExtensionsSucceeds("extensions_real.pem", &extensions, &data);

  ASSERT_EQ(7u, extensions.size());

  auto iter = extensions.find(KeyUsageOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_TRUE(iter->second.critical);
  EXPECT_EQ(4u, iter->second.value.Length());

  iter = extensions.find(BasicConstraintsOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_TRUE(iter->second.critical);
  EXPECT_EQ(8u, iter->second.value.Length());

  iter = extensions.find(CertificatePoliciesOid());
  ASSERT_TRUE(iter != extensions.end());
  EXPECT_FALSE(iter->second.critical);
  EXPECT_EQ(16u, iter->second.value.Length());

  // TODO(eroman): Verify the other 4 extensions' values.
}

// Reads a PEM file containing a block "BASIC CONSTRAINTS". This input will
// be passed to ParseExtension, and the results filled in |out|.
bool ParseBasicConstraintsFromFile(const std::string& file_name,
                                   ParsedBasicConstraints* out) {
  std::string data;
  const PemBlockMapping mappings[] = {
      {"BASIC CONSTRAINTS", &data},
  };

  EXPECT_TRUE(ReadTestDataFromPemFile(GetFilePath(file_name), mappings));
  return ParseBasicConstraints(der::Input(&data), out);
}

// Parses a BasicConstraints with no CA or pathlen.
TEST(ParseBasicConstraintsTest, NotCa) {
  ParsedBasicConstraints constraints;
  ASSERT_TRUE(ParseBasicConstraintsFromFile("basic_constraints_not_ca.pem",
                                            &constraints));
  EXPECT_FALSE(constraints.is_ca);
  EXPECT_FALSE(constraints.has_path_len);
}

// Parses a BasicConstraints with CA but no pathlen.
TEST(ParseBasicConstraintsTest, CaNoPath) {
  ParsedBasicConstraints constraints;
  ASSERT_TRUE(ParseBasicConstraintsFromFile("basic_constraints_ca_no_path.pem",
                                            &constraints));
  EXPECT_TRUE(constraints.is_ca);
  EXPECT_FALSE(constraints.has_path_len);
}

// Parses a BasicConstraints with CA and pathlen of 9.
TEST(ParseBasicConstraintsTest, CaPath9) {
  ParsedBasicConstraints constraints;
  ASSERT_TRUE(ParseBasicConstraintsFromFile("basic_constraints_ca_path_9.pem",
                                            &constraints));
  EXPECT_TRUE(constraints.is_ca);
  EXPECT_TRUE(constraints.has_path_len);
  EXPECT_EQ(9u, constraints.path_len);
}

// Parses a BasicConstraints with CA and pathlen of 255 (largest allowed size).
TEST(ParseBasicConstraintsTest, Pathlen255) {
  ParsedBasicConstraints constraints;
  ASSERT_TRUE(ParseBasicConstraintsFromFile("basic_constraints_pathlen_255.pem",
                                            &constraints));
  EXPECT_TRUE(constraints.is_ca);
  EXPECT_TRUE(constraints.has_path_len);
  EXPECT_EQ(255, constraints.path_len);
}

// Parses a BasicConstraints with CA and pathlen of 256 (too large).
TEST(ParseBasicConstraintsTest, Pathlen256) {
  ParsedBasicConstraints constraints;
  ASSERT_FALSE(ParseBasicConstraintsFromFile(
      "basic_constraints_pathlen_256.pem", &constraints));
}

// Parses a BasicConstraints with CA and a negative pathlen.
TEST(ParseBasicConstraintsTest, NegativePath) {
  ParsedBasicConstraints constraints;
  ASSERT_FALSE(ParseBasicConstraintsFromFile(
      "basic_constraints_negative_path.pem", &constraints));
}

// Parses a BasicConstraints with CA and pathlen that is very large (and
// couldn't fit in a 64-bit integer).
TEST(ParseBasicConstraintsTest, PathTooLarge) {
  ParsedBasicConstraints constraints;
  ASSERT_FALSE(ParseBasicConstraintsFromFile(
      "basic_constraints_path_too_large.pem", &constraints));
}

// Parses a BasicConstraints with CA explicitly set to false. This violates
// DER-encoding rules, however is commonly used, so it is accepted.
TEST(ParseBasicConstraintsTest, CaFalse) {
  ParsedBasicConstraints constraints;
  ASSERT_TRUE(ParseBasicConstraintsFromFile("basic_constraints_ca_false.pem",
                                            &constraints));
  EXPECT_FALSE(constraints.is_ca);
  EXPECT_FALSE(constraints.has_path_len);
}

// Parses a BasicConstraints with CA set to true and an unexpected NULL at
// the end.
TEST(ParseBasicConstraintsTest, UnconsumedData) {
  ParsedBasicConstraints constraints;
  ASSERT_FALSE(ParseBasicConstraintsFromFile(
      "basic_constraints_unconsumed_data.pem", &constraints));
}

// Parses a BasicConstraints with CA omitted (false), but with a pathlen of 1.
// This is valid DER for the ASN.1, however is not valid when interpreting the
// BasicConstraints at a higher level.
TEST(ParseBasicConstraintsTest, PathLenButNotCa) {
  ParsedBasicConstraints constraints;
  ASSERT_TRUE(ParseBasicConstraintsFromFile(
      "basic_constraints_pathlen_not_ca.pem", &constraints));
  EXPECT_FALSE(constraints.is_ca);
  EXPECT_TRUE(constraints.has_path_len);
  EXPECT_EQ(1u, constraints.path_len);
}

// Parses a KeyUsage with a single 0 bit.
TEST(ParseKeyUsageTest, OneBitAllZeros) {
  const uint8_t der[] = {
      0x03, 0x02,  // BIT STRING
      0x07,        // Number of unused bits
      0x00,        // bits
  };

  der::BitString key_usage;
  ASSERT_FALSE(ParseKeyUsage(der::Input(der), &key_usage));
}

// Parses a KeyUsage with 32 bits that are all 0.
TEST(ParseKeyUsageTest, 32BitsAllZeros) {
  const uint8_t der[] = {
      0x03, 0x05,  // BIT STRING
      0x00,        // Number of unused bits
      0x00, 0x00, 0x00, 0x00,
  };

  der::BitString key_usage;
  ASSERT_FALSE(ParseKeyUsage(der::Input(der), &key_usage));
}

// Parses a KeyUsage with 32 bits, one of which is 1 (but not in recognized
// set).
TEST(ParseKeyUsageTest, 32BitsOneSet) {
  const uint8_t der[] = {
      0x03, 0x05,  // BIT STRING
      0x00,        // Number of unused bits
      0x00, 0x00, 0x00, 0x02,
  };

  der::BitString key_usage;
  ASSERT_TRUE(ParseKeyUsage(der::Input(der), &key_usage));

  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DIGITAL_SIGNATURE));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_NON_REPUDIATION));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_ENCIPHERMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DATA_ENCIPHERMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_AGREEMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_CRL_SIGN));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_ENCIPHER_ONLY));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DECIPHER_ONLY));
}

// Parses a KeyUsage containing bit string 101.
TEST(ParseKeyUsageTest, ThreeBits) {
  const uint8_t der[] = {
      0x03, 0x02,  // BIT STRING
      0x05,        // Number of unused bits
      0xA0,        // bits
  };

  der::BitString key_usage;
  ASSERT_TRUE(ParseKeyUsage(der::Input(der), &key_usage));

  EXPECT_TRUE(key_usage.AssertsBit(KEY_USAGE_BIT_DIGITAL_SIGNATURE));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_NON_REPUDIATION));
  EXPECT_TRUE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_ENCIPHERMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DATA_ENCIPHERMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_AGREEMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_CRL_SIGN));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_ENCIPHER_ONLY));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DECIPHER_ONLY));
}

// Parses a KeyUsage containing DECIPHER_ONLY, which is the
// only bit that doesn't fit in the first byte.
TEST(ParseKeyUsageTest, DecipherOnly) {
  const uint8_t der[] = {
      0x03, 0x03,  // BIT STRING
      0x07,        // Number of unused bits
      0x00, 0x80,  // bits
  };

  der::BitString key_usage;
  ASSERT_TRUE(ParseKeyUsage(der::Input(der), &key_usage));

  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DIGITAL_SIGNATURE));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_NON_REPUDIATION));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_ENCIPHERMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_DATA_ENCIPHERMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_AGREEMENT));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_CRL_SIGN));
  EXPECT_FALSE(key_usage.AssertsBit(KEY_USAGE_BIT_ENCIPHER_ONLY));
  EXPECT_TRUE(key_usage.AssertsBit(KEY_USAGE_BIT_DECIPHER_ONLY));
}

// Parses an empty KeyUsage.
TEST(ParseKeyUsageTest, Empty) {
  const uint8_t der[] = {
      0x03, 0x01,  // BIT STRING
      0x00,        // Number of unused bits
  };

  der::BitString key_usage;
  ASSERT_FALSE(ParseKeyUsage(der::Input(der), &key_usage));
}

}  // namespace

}  // namespace net
