// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_version_manager.h"

#include "net/quic/core/quic_versions.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicVersionManagerTest, QuicVersionManager) {
  QuicFlagSaver flags;
  FLAGS_quic_reloadable_flag_quic_enable_version_38 = false;
  QuicVersionManager manager(AllSupportedVersions());
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());

  FLAGS_quic_reloadable_flag_quic_enable_version_38 = true;
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  ASSERT_EQ(4u, manager.GetSupportedVersions().size());
  EXPECT_EQ(QUIC_VERSION_38, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_37, manager.GetSupportedVersions()[1]);
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[2]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[3]);

  FLAGS_quic_enable_version_39 = true;
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  ASSERT_EQ(5u, manager.GetSupportedVersions().size());
  EXPECT_EQ(QUIC_VERSION_39, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_38, manager.GetSupportedVersions()[1]);
  EXPECT_EQ(QUIC_VERSION_37, manager.GetSupportedVersions()[2]);
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[3]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[4]);

  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  ASSERT_EQ(5u, manager.GetSupportedVersions().size());
  EXPECT_EQ(QUIC_VERSION_39, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_38, manager.GetSupportedVersions()[1]);
  EXPECT_EQ(QUIC_VERSION_37, manager.GetSupportedVersions()[2]);
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[3]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[4]);
}

}  // namespace
}  // namespace test
}  // namespace net
