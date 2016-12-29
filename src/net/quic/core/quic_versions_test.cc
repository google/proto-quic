// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_versions.h"

#include "net/quic/core/quic_flags.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicVersionsTest, QuicVersionToQuicTag) {
// If you add a new version to the QuicVersion enum you will need to add a new
// case to QuicVersionToQuicTag, otherwise this test will fail.

// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  // Any logs would indicate an unsupported version which we don't expect.
  ScopedMockLog log(kDoNotCaptureLogsYet);
  EXPECT_CALL(log, Log(_, _, _)).Times(0);
  log.StartCapturingLogs();
#endif

  // Explicitly test a specific version.
  EXPECT_EQ(MakeQuicTag('Q', '0', '3', '4'),
            QuicVersionToQuicTag(QUIC_VERSION_34));

  // Loop over all supported versions and make sure that we never hit the
  // default case (i.e. all supported versions should be successfully converted
  // to valid QuicTags).
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_LT(0u, QuicVersionToQuicTag(version));
  }
}

TEST(QuicVersionsTest, QuicVersionToQuicTagUnsupported) {
// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  // TODO(rjshade): Change to DFATAL once we actually support multiple versions,
  // and QuicConnectionTest::SendVersionNegotiationPacket can be changed to use
  // mis-matched versions rather than relying on QUIC_VERSION_UNSUPPORTED.
  ScopedMockLog log(kDoNotCaptureLogsYet);
  EXPECT_CALL(log, Log(base_logging::ERROR, _, "Unsupported QuicVersion: 0"))
      .Times(1);
  log.StartCapturingLogs();
#endif

  EXPECT_EQ(0u, QuicVersionToQuicTag(QUIC_VERSION_UNSUPPORTED));
}

TEST(QuicVersionsTest, QuicTagToQuicVersion) {
// If you add a new version to the QuicVersion enum you will need to add a new
// case to QuicTagToQuicVersion, otherwise this test will fail.

// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  // Any logs would indicate an unsupported version which we don't expect.
  ScopedMockLog log(kDoNotCaptureLogsYet);
  EXPECT_CALL(log, Log(_, _, _)).Times(0);
  log.StartCapturingLogs();
#endif

  // Explicitly test specific versions.
  EXPECT_EQ(QUIC_VERSION_34,
            QuicTagToQuicVersion(MakeQuicTag('Q', '0', '3', '4')));

  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];

    // Get the tag from the version (we can loop over QuicVersions easily).
    QuicTag tag = QuicVersionToQuicTag(version);
    EXPECT_LT(0u, tag);

    // Now try converting back.
    QuicVersion tag_to_quic_version = QuicTagToQuicVersion(tag);
    EXPECT_EQ(version, tag_to_quic_version);
    EXPECT_NE(QUIC_VERSION_UNSUPPORTED, tag_to_quic_version);
  }
}

TEST(QuicVersionsTest, QuicTagToQuicVersionUnsupported) {
// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  ScopedMockLog log(kDoNotCaptureLogsYet);
#ifndef NDEBUG
  EXPECT_CALL(log,
              Log(base_logging::INFO, _, "Unsupported QuicTag version: FAKE"))
      .Times(1);
#endif
  log.StartCapturingLogs();
#endif

  EXPECT_EQ(QUIC_VERSION_UNSUPPORTED,
            QuicTagToQuicVersion(MakeQuicTag('F', 'A', 'K', 'E')));
}

TEST(QuicVersionsTest, QuicVersionToString) {
  EXPECT_EQ("QUIC_VERSION_34", QuicVersionToString(QUIC_VERSION_34));
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED",
            QuicVersionToString(QUIC_VERSION_UNSUPPORTED));

  QuicVersion single_version[] = {QUIC_VERSION_34};
  QuicVersionVector versions_vector;
  for (size_t i = 0; i < arraysize(single_version); ++i) {
    versions_vector.push_back(single_version[i]);
  }
  EXPECT_EQ("QUIC_VERSION_34", QuicVersionVectorToString(versions_vector));

  QuicVersion multiple_versions[] = {QUIC_VERSION_UNSUPPORTED, QUIC_VERSION_34};
  versions_vector.clear();
  for (size_t i = 0; i < arraysize(multiple_versions); ++i) {
    versions_vector.push_back(multiple_versions[i]);
  }
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_34",
            QuicVersionVectorToString(versions_vector));

  // Make sure that all supported versions are present in QuicVersionToString.
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_NE("QUIC_VERSION_UNSUPPORTED", QuicVersionToString(version));
  }
}

TEST(QuicVersionsTest, FilterSupportedVersionsNo34) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36, QUIC_VERSION_37};

  FLAGS_quic_reloadable_flag_quic_disable_version_34 = true;
  FLAGS_quic_reloadable_flag_quic_enable_version_36_v3 = false;
  FLAGS_quic_reloadable_flag_quic_enable_version_37 = false;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(1u, filtered_versions.size());
  EXPECT_EQ(QUIC_VERSION_35, filtered_versions[0]);
}

TEST(QuicVersionsTest, FilterSupportedVersionsNo36) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36, QUIC_VERSION_37};

  FLAGS_quic_reloadable_flag_quic_disable_version_34 = false;
  FLAGS_quic_reloadable_flag_quic_enable_version_36_v3 = false;
  FLAGS_quic_reloadable_flag_quic_enable_version_37 = false;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(2u, filtered_versions.size());
  EXPECT_EQ(QUIC_VERSION_34, filtered_versions[0]);
  EXPECT_EQ(QUIC_VERSION_35, filtered_versions[1]);
}

TEST(QuicVersionsTest, FilterSupportedVersionsNo37) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36, QUIC_VERSION_37};

  FLAGS_quic_reloadable_flag_quic_disable_version_34 = false;
  FLAGS_quic_reloadable_flag_quic_enable_version_36_v3 = true;
  FLAGS_quic_reloadable_flag_quic_enable_version_37 = false;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(3u, filtered_versions.size());
  EXPECT_EQ(QUIC_VERSION_34, filtered_versions[0]);
  EXPECT_EQ(QUIC_VERSION_35, filtered_versions[1]);
  EXPECT_EQ(QUIC_VERSION_36, filtered_versions[2]);
}

TEST(QuicVersionsTest, FilterSupportedVersionsAllVersions) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36, QUIC_VERSION_37};

  FLAGS_quic_reloadable_flag_quic_disable_version_34 = false;
  FLAGS_quic_reloadable_flag_quic_enable_version_36_v3 = true;
  FLAGS_quic_reloadable_flag_quic_enable_version_37 = true;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(all_versions, filtered_versions);
}

TEST(QuicVersionsTest, LookUpVersionByIndex) {
  QuicVersionVector all_versions = {QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36, QUIC_VERSION_37};
  int version_count = all_versions.size();
  for (int i = -5; i <= version_count + 1; ++i) {
    if (i >= 0 && i < version_count) {
      EXPECT_EQ(all_versions[i], VersionOfIndex(all_versions, i)[0]);
    } else {
      EXPECT_EQ(QUIC_VERSION_UNSUPPORTED, VersionOfIndex(all_versions, i)[0]);
    }
  }
}

}  // namespace
}  // namespace test
}  // namespace net
