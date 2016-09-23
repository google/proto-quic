// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_TEST_HELPERS_H_
#define NET_CERT_INTERNAL_TEST_HELPERS_H_

#include <stddef.h>

#include <ostream>
#include <string>
#include <vector>

#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/trust_store.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace der {

// This function is used by GTest to support EXPECT_EQ() for der::Input.
void PrintTo(const Input& data, ::std::ostream* os);

}  // namespace der

// Parses |s| as a DER SEQUENCE TLV and returns a der::Input corresponding to
// the value portion. On error returns an empty der::Input and adds a gtest
// failure.
//
// The returned der::Input() is only valid so long as the input string is alive
// and is not mutated.
der::Input SequenceValueFromString(const std::string* s);

// Helper structure that maps a PEM block header (for instance "CERTIFICATE") to
// the destination where the value for that block should be written.
struct PemBlockMapping {
  // The name of the PEM header. Example "CERTIFICATE".
  const char* block_name;

  // The destination where the read value should be written to.
  std::string* value;

  // True to indicate that the block is not required to be present. If the
  // block is optional and is not present, then |value| will not be modified.
  bool optional;
};

// ReadTestDataFromPemFile() is a helper function that reads a PEM test file
// rooted in the "src/" directory.
//
//   * file_path_ascii:
//       The path to the PEM file, relative to src. For instance
//       "net/data/verify_signed_data_unittest/foopy.pem"
//
//   * mappings:
//       An array of length |mappings_length| which maps the expected PEM
//       headers to the destination to write its data.
//
// The function ensures that each of the chosen mappings is satisfied exactly
// once. In other words, the header must be present (unless marked as
// optional=true), have valid data, and appear no more than once.
::testing::AssertionResult ReadTestDataFromPemFile(
    const std::string& file_path_ascii,
    const PemBlockMapping* mappings,
    size_t mappings_length);

// This is the same as the variant above, however it uses template magic so an
// mappings array can be passed in directly (and the correct length is
// inferred).
template <size_t N>
::testing::AssertionResult ReadTestDataFromPemFile(
    const std::string& file_path_ascii,
    const PemBlockMapping(&mappings)[N]) {
  return ReadTestDataFromPemFile(file_path_ascii, mappings, N);
}

// Reads a test case from |file_path_ascii| (which is relative to //src). Test
// cases are comprised of a certificate chain, trust anchor, a timestamp to
// validate at, and the expected result of verification.
// Generally |file_path_ascii| will start with:
//   net/data/verify_certificate_chain_unittest/
void ReadVerifyCertChainTestFromFile(const std::string& file_path_ascii,
                                     ParsedCertificateList* chain,
                                     scoped_refptr<TrustAnchor>* trust_anchor,
                                     der::GeneralizedTime* time,
                                     bool* verify_result,
                                     std::string* expected_errors);

// Reads a data file relative to the src root directory.
std::string ReadTestFileToString(const std::string& file_path_ascii);

}  // namespace net

#endif  // NET_CERT_INTERNAL_TEST_HELPERS_H_
