// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_NIST_PKITS_UNITTEST_H_
#define NET_CERT_INTERNAL_NIST_PKITS_UNITTEST_H_

#include "net/cert/internal/test_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"

// Parameterized test class for PKITS tests.
// The instantiating code should define a PkitsTestDelegate with an appropriate
// static Verify method, and then INSTANTIATE_TYPED_TEST_CASE_P for each
// testcase (each TYPED_TEST_CASE_P in pkits_testcases-inl.h).
template <typename PkitsTestDelegate>
class PkitsTest : public ::testing::Test {
 public:
  template <size_t num_certs, size_t num_crls>
  bool Verify(const char* const (&cert_names)[num_certs],
              const char* const (&crl_names)[num_crls]) {
    std::vector<std::string> cert_ders;
    for (const std::string& s : cert_names)
      cert_ders.push_back(net::ReadTestFileToString(
          "net/third_party/nist-pkits/certs/" + s + ".crt"));
    std::vector<std::string> crl_ders;
    for (const std::string& s : crl_names)
      crl_ders.push_back(net::ReadTestFileToString(
          "net/third_party/nist-pkits/crls/" + s + ".crl"));
    return PkitsTestDelegate::Verify(cert_ders, crl_ders);
  }
};

// Inline the generated test code:
#include "net/third_party/nist-pkits/pkits_testcases-inl.h"

#endif  // NET_CERT_INTERNAL_NIST_PKITS_UNITTEST_H_
