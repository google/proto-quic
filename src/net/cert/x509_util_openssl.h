// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_X509_UTIL_OPENSSL_H_
#define NET_CERT_X509_UTIL_OPENSSL_H_

#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace base {
class Time;
}  // namespace base

namespace net {

// A collection of helper functions to fetch data from OpenSSL X509 certificates
// into more convenient std / base datatypes.
namespace x509_util {

bool NET_EXPORT ParsePrincipalKeyAndValue(X509_NAME_ENTRY* entry,
                                          std::string* key,
                                          std::string* value);

bool NET_EXPORT ParsePrincipalKeyAndValueByIndex(X509_NAME* name,
                                                 int index,
                                                 std::string* key,
                                                 std::string* value);

bool NET_EXPORT ParsePrincipalValueByIndex(X509_NAME* name,
                                           int index,
                                           std::string* value);

bool NET_EXPORT ParsePrincipalValueByNID(X509_NAME* name,
                                         int nid,
                                         std::string* value);

bool NET_EXPORT ParseDate(ASN1_TIME* x509_time, base::Time* time);

// DER-encodes |x509|, caching the encoding in a structure owned by
// the X509. On success, returns true, and sets |*out_der| to point to
// the encoding. The StringPiece is valid as long as |x509| is not
// freed.
//
// Note: this caches the encoding, so |x509| must not be modified
// after the first call to this function.
bool NET_EXPORT GetDER(X509* x509, base::StringPiece* out_der);

} // namespace x509_util

} // namespace net

#endif  // NET_CERT_X509_UTIL_OPENSSL_H_
