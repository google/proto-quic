// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <algorithm>

#include "base/time/time.h"
#include "crypto/sha2.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

#include "net/cert/ct_known_logs_static-inc.h"

}  // namespace

TEST(CTKnownLogsTest, GoogleIDsAreSorted) {
  ASSERT_TRUE(std::is_sorted(std::begin(kGoogleLogIDs), std::end(kGoogleLogIDs),
                             [](const char* a, const char* b) {
                               return memcmp(a, b, crypto::kSHA256Length) < 0;
                             }));
}

TEST(CTKnownLogsTest, DisallowedLogsAreSortedByLogID) {
  ASSERT_TRUE(std::is_sorted(
      std::begin(kDisqualifiedCTLogList), std::end(kDisqualifiedCTLogList),
      [](const DisqualifiedCTLogInfo& a, const DisqualifiedCTLogInfo& b) {
        return memcmp(a.log_id, b.log_id, crypto::kSHA256Length) < 0;
      }));
}

}  // namespace net
