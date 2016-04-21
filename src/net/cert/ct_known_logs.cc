// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_known_logs.h"

#include <stddef.h>
#include <string.h>

#include <algorithm>
#include <iterator>

#include "base/logging.h"
#include "base/macros.h"
#include "crypto/sha2.h"

#if !defined(OS_NACL)
#include "net/cert/ct_log_verifier.h"
#endif

namespace net {

namespace ct {

namespace {

#include "net/cert/ct_known_logs_static-inc.h"

}  // namespace

#if !defined(OS_NACL)
std::vector<scoped_refptr<const CTLogVerifier>>
CreateLogVerifiersForKnownLogs() {
  std::vector<scoped_refptr<const CTLogVerifier>> verifiers;
  for (const auto& log : kCTLogList) {
    base::StringPiece key(log.log_key, log.log_key_length);
    verifiers.push_back(CTLogVerifier::Create(key, log.log_name, log.log_url));
    // Make sure no null logs enter verifiers. Parsing of all known logs should
    // succeed.
    CHECK(verifiers.back().get());
  }

  return verifiers;
}
#endif

bool IsLogOperatedByGoogle(base::StringPiece log_id) {
  CHECK_EQ(log_id.size(), crypto::kSHA256Length);

  return std::binary_search(std::begin(kGoogleLogIDs), std::end(kGoogleLogIDs),
                            log_id.data(), [](const char* a, const char* b) {
                              return memcmp(a, b, crypto::kSHA256Length) < 0;
                            });
}

}  // namespace ct

}  // namespace net

