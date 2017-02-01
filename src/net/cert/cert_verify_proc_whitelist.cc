// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_whitelist.h"

#include <cstdlib>

#include "net/base/lookup_string_in_fixed_set.h"
#include "net/cert/x509_certificate.h"

namespace net {

namespace {

// clang-format off
// SHA-256 hashes of the subjectPublicKeyInfos of root certificates owned
// or operated by WoSign, including that of StartCom. For the certificates,
// see //net/data/ssl/wosign.
const uint8_t kWosignKeys[][crypto::kSHA256Length] = {
    { 0x15, 0x28, 0x39, 0x7d, 0xa2, 0x12, 0x89, 0x0a,
      0x83, 0x0b, 0x0b, 0x95, 0xa5, 0x99, 0x68, 0xce,
      0xf2, 0x34, 0x77, 0x37, 0x79, 0xdf, 0x51, 0x81,
      0xcf, 0x10, 0xfa, 0x64, 0x75, 0x34, 0xbb, 0x65 },
    { 0x38, 0x1a, 0x3f, 0xc7, 0xa8, 0xb0, 0x82, 0xfa,
      0x28, 0x61, 0x3a, 0x4d, 0x07, 0xf2, 0xc7, 0x55,
      0x3f, 0x4e, 0x19, 0x18, 0xee, 0x07, 0xca, 0xa9,
      0xe8, 0xb7, 0xce, 0xde, 0x5a, 0x9c, 0xa0, 0x6a },
    { 0x7a, 0xed, 0xdd, 0xf3, 0x6b, 0x18, 0xf8, 0xac,
      0xb7, 0x37, 0x9f, 0xe1, 0xce, 0x18, 0x32, 0x12,
      0xb2, 0x35, 0x0d, 0x07, 0x88, 0xab, 0xe0, 0xe8,
      0x24, 0x57, 0xbe, 0x9b, 0xad, 0xad, 0x6d, 0x54 },
    { 0x9d, 0x98, 0xa1, 0xfb, 0x60, 0x53, 0x8c, 0x4c,
      0xc4, 0x85, 0x7f, 0xf1, 0xa8, 0xc8, 0x03, 0x4f,
      0xaf, 0x6f, 0xc5, 0x92, 0x09, 0x3f, 0x61, 0x99,
      0x94, 0xb2, 0xc8, 0x13, 0xd2, 0x50, 0xb8, 0x64 },
    { 0xd6, 0xa1, 0x84, 0x43, 0xd3, 0x48, 0xdb, 0x99,
      0x4f, 0x93, 0x4c, 0xcd, 0x8e, 0x63, 0x5d, 0x83,
      0x3a, 0x27, 0xac, 0x1e, 0x56, 0xf8, 0xaf, 0xaf,
      0x7c, 0x97, 0xcb, 0x4f, 0x43, 0xea, 0xb6, 0x8b },
    { 0xdb, 0x15, 0xc0, 0x06, 0x2b, 0x52, 0x0f, 0x31,
      0x8a, 0x19, 0xda, 0xcf, 0xec, 0xd6, 0x4f, 0x9e,
      0x7a, 0x3f, 0xbe, 0x60, 0x9f, 0xd5, 0x86, 0x79,
      0x6f, 0x20, 0xae, 0x02, 0x8e, 0x8e, 0x30, 0x58 },
    { 0xe4, 0x2f, 0x24, 0xbd, 0x4d, 0x37, 0xf4, 0xaa,
      0x2e, 0x56, 0xb9, 0x79, 0xd8, 0x3d, 0x1e, 0x65,
      0x21, 0x9f, 0xe0, 0xe9, 0xe3, 0xa3, 0x82, 0xa1,
      0xb3, 0xcb, 0x66, 0xc9, 0x39, 0x55, 0xde, 0x75 },
};
// clang-format on

// Comparator to compare a (SHA-256) HashValue with a uint8_t array containing
// a raw SHA-256 hash. Return value follows memcmp semantics.
int CompareHashValueToRawHash(const void* key, const void* element) {
  const HashValue* search_key = reinterpret_cast<const HashValue*>(key);
  return memcmp(search_key->data(), element, search_key->size());
}

namespace wosign {
#include "net/data/ssl/wosign/wosign_domains-inc.cc"
}  // namespace

}  // namespace

bool IsNonWhitelistedCertificate(const X509Certificate& cert,
                                 const HashValueVector& public_key_hashes,
                                 base::StringPiece hostname) {
  for (const auto& hash : public_key_hashes) {
    if (hash.tag != HASH_VALUE_SHA256)
      continue;

    // Check for WoSign/StartCom certificates.
    if (bsearch(&hash, kWosignKeys, arraysize(kWosignKeys),
                crypto::kSHA256Length, CompareHashValueToRawHash) != nullptr) {
      // 2016-10-21 00:00:00 UTC
      const base::Time last_wosign_cert =
          base::Time::UnixEpoch() + base::TimeDelta::FromSeconds(1477008000);

      // Don't allow new certificates.
      if (cert.valid_start().is_null() || cert.valid_start().is_max() ||
          cert.valid_start() > last_wosign_cert) {
        return true;
      }

      // Don't allow certificates from non-whitelisted hosts.
      return !IsWhitelistedHost(wosign::kDafsa, arraysize(wosign::kDafsa),
                                hostname);
    }
  }
  return false;
}

bool IsWhitelistedHost(const unsigned char* graph,
                       size_t graph_length,
                       base::StringPiece host) {
  if (host.empty())
    return false;

  size_t end = host.length();

  // Skip trailing '.', if any.
  if (host[end - 1] == '.') {
    --end;
  }

  // Reverse through each of the domain components, trying to see if the
  // domain is on the whitelist. For example, the string
  // "www.domain.example.com" would be processed by first searching
  // for "com", then "example.com", then "domain.example.com". The
  // loop will terminate when there are no more distinct label separators,
  // and thus the final check for "www.domain.example.com".
  size_t start = end;
  while (start != 0 &&
         (start = host.rfind('.', start - 1)) != base::StringPiece::npos) {
    const char* domain_str = host.data() + start + 1;
    size_t domain_length = end - start - 1;
    if (domain_length == 0)
      return false;
    if (LookupStringInFixedSet(graph, graph_length, domain_str,
                               domain_length) != kDafsaNotFound) {
      return true;
    }
  }

  return LookupStringInFixedSet(graph, graph_length, host.data(), end) !=
         kDafsaNotFound;
}

}  // namespace net
