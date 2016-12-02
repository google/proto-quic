// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_version_manager.h"

#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_versions.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicVersionManagerTest, QuicVersionManager) {
  QuicFlagSaver flags;
  FLAGS_quic_enable_version_36_v3 = false;
  QuicVersionManager manager(AllSupportedVersions());
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  FLAGS_quic_enable_version_36_v3 = true;
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[1]);
}

}  // namespace
}  // namespace test
}  // namespace net
