// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/traffic_annotation/auditor/traffic_annotation_auditor.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

#define TEST_HASH_CODE(X)                                  \
  EXPECT_EQ(TrafficAnnotationAuditor::ComputeHashValue(X), \
            net::DefineNetworkTrafficAnnotation(X, "").unique_id_hash_code)
}

using namespace testing;

typedef ::testing::Test TrafficAnnotationAuditorTest;

// Tests if the two hash computation functions have the same result.
TEST_F(TrafficAnnotationAuditorTest, HashFunctionCheck) {
  TEST_HASH_CODE("test");
  TEST_HASH_CODE("unique_id");
  TEST_HASH_CODE("123_id");
  TEST_HASH_CODE("ID123");
  TEST_HASH_CODE(
      "a_unique_looooooooooooooooooooooooooooooooooooooooooooooooooooooong_id");
}