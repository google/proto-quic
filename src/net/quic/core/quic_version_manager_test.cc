// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_version_manager.h"

#include "net/quic/core/quic_versions.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/quic_test_utils.h"

namespace net {
namespace test {
namespace {

class QuicVersionManagerTest : public QuicTest {};

TEST_F(QuicVersionManagerTest, QuicVersionManager) {
  SetQuicFlag(&FLAGS_quic_enable_version_40, false);
  FLAGS_quic_reloadable_flag_quic_enable_version_39 = false;
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

  FLAGS_quic_reloadable_flag_quic_enable_version_39 = true;
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  ASSERT_EQ(5u, manager.GetSupportedVersions().size());
  EXPECT_EQ(QUIC_VERSION_39, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_38, manager.GetSupportedVersions()[1]);
  EXPECT_EQ(QUIC_VERSION_37, manager.GetSupportedVersions()[2]);
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[3]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[4]);

  SetQuicFlag(&FLAGS_quic_enable_version_40, true);
  ASSERT_EQ(6u, manager.GetSupportedVersions().size());
  EXPECT_EQ(QUIC_VERSION_40, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_39, manager.GetSupportedVersions()[1]);
  EXPECT_EQ(QUIC_VERSION_38, manager.GetSupportedVersions()[2]);
  EXPECT_EQ(QUIC_VERSION_37, manager.GetSupportedVersions()[3]);
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[4]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[5]);

  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  ASSERT_EQ(6u, manager.GetSupportedVersions().size());
  EXPECT_EQ(QUIC_VERSION_40, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_39, manager.GetSupportedVersions()[1]);
  EXPECT_EQ(QUIC_VERSION_38, manager.GetSupportedVersions()[2]);
  EXPECT_EQ(QUIC_VERSION_37, manager.GetSupportedVersions()[3]);
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[4]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[5]);
}

}  // namespace
}  // namespace test
}  // namespace net
