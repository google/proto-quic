// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_known_logs.h"

#include <algorithm>

#include "base/logging.h"
#include "base/macros.h"
#include "crypto/sha2.h"
#include "net/cert/ct_known_logs_static.h"

#if !defined(OS_NACL)
#include "net/cert/ct_log_verifier.h"
#endif

namespace net {

namespace ct {

namespace {

int log_ids_compare(const char* log_id, const char* lookup_id) {
  return strncmp(log_id, lookup_id, crypto::kSHA256Length) < 0;
}

}  // namespace

#if !defined(OS_NACL)
std::vector<scoped_refptr<const CTLogVerifier>>
CreateLogVerifiersForKnownLogs() {
  std::vector<scoped_refptr<const CTLogVerifier>> verifiers;
  for (size_t i = 0; i < arraysize(kCTLogList); ++i) {
    const CTLogInfo& log(kCTLogList[i]);
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
  // No callers should provide a log_id that's not of the expected length
  // (log IDs are SHA-256 hashes of the key and are always 32 bytes).
  // Without this DCHECK (i.e. in production) this function would always
  // return false.
  DCHECK_EQ(log_id.size(), arraysize(kGoogleLogIDs[0]) - 1);

  auto p = std::lower_bound(kGoogleLogIDs, kGoogleLogIDs + kNumGoogleLogs,
                            log_id.data(), &log_ids_compare);
  if ((p == kGoogleLogIDs + kNumGoogleLogs) ||
      log_id != base::StringPiece(*p, crypto::kSHA256Length)) {
    return false;
  }

  return true;
}

}  // namespace ct

}  // namespace net

