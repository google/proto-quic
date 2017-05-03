// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_versions.h"

#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/quic_test_utils.h"

namespace net {
namespace test {
namespace {

class QuicVersionsTest : public QuicTest {};

TEST_F(QuicVersionsTest, QuicVersionToQuicTag) {
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
  EXPECT_EQ(MakeQuicTag('Q', '0', '3', '5'),
            QuicVersionToQuicTag(QUIC_VERSION_35));

  // Loop over all supported versions and make sure that we never hit the
  // default case (i.e. all supported versions should be successfully converted
  // to valid QuicTags).
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_LT(0u, QuicVersionToQuicTag(version));
  }
}

TEST_F(QuicVersionsTest, QuicVersionToQuicTagUnsupported) {
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

TEST_F(QuicVersionsTest, QuicTagToQuicVersion) {
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
  EXPECT_EQ(QUIC_VERSION_35,
            QuicTagToQuicVersion(MakeQuicTag('Q', '0', '3', '5')));

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

TEST_F(QuicVersionsTest, QuicTagToQuicVersionUnsupported) {
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

TEST_F(QuicVersionsTest, QuicVersionToString) {
  EXPECT_EQ("QUIC_VERSION_35", QuicVersionToString(QUIC_VERSION_35));
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED",
            QuicVersionToString(QUIC_VERSION_UNSUPPORTED));

  QuicVersion single_version[] = {QUIC_VERSION_35};
  QuicVersionVector versions_vector;
  for (size_t i = 0; i < arraysize(single_version); ++i) {
    versions_vector.push_back(single_version[i]);
  }
  EXPECT_EQ("QUIC_VERSION_35", QuicVersionVectorToString(versions_vector));

  QuicVersion multiple_versions[] = {QUIC_VERSION_UNSUPPORTED, QUIC_VERSION_35};
  versions_vector.clear();
  for (size_t i = 0; i < arraysize(multiple_versions); ++i) {
    versions_vector.push_back(multiple_versions[i]);
  }
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_35",
            QuicVersionVectorToString(versions_vector));

  // Make sure that all supported versions are present in QuicVersionToString.
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_NE("QUIC_VERSION_UNSUPPORTED", QuicVersionToString(version));
  }
}

TEST_F(QuicVersionsTest, FilterSupportedVersionsNo38) {
  QuicVersionVector all_versions = {QUIC_VERSION_35, QUIC_VERSION_36,
                                    QUIC_VERSION_37, QUIC_VERSION_38,
                                    QUIC_VERSION_39};

  FLAGS_quic_reloadable_flag_quic_enable_version_38 = false;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(3u, filtered_versions.size());
  EXPECT_EQ(QUIC_VERSION_35, filtered_versions[0]);
  EXPECT_EQ(QUIC_VERSION_36, filtered_versions[1]);
  EXPECT_EQ(QUIC_VERSION_37, filtered_versions[2]);
}

TEST_F(QuicVersionsTest, FilterSupportedVersionsNo39) {
  QuicVersionVector all_versions = {QUIC_VERSION_35, QUIC_VERSION_36,
                                    QUIC_VERSION_37, QUIC_VERSION_38,
                                    QUIC_VERSION_39};

  FLAGS_quic_reloadable_flag_quic_enable_version_38 = true;
  FLAGS_quic_reloadable_flag_quic_enable_version_39 = false;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(4u, filtered_versions.size());
  EXPECT_EQ(QUIC_VERSION_35, filtered_versions[0]);
  EXPECT_EQ(QUIC_VERSION_36, filtered_versions[1]);
  EXPECT_EQ(QUIC_VERSION_37, filtered_versions[2]);
  EXPECT_EQ(QUIC_VERSION_38, filtered_versions[3]);
}

TEST_F(QuicVersionsTest, FilterSupportedVersionsAllVersions) {
  QuicVersionVector all_versions = {QUIC_VERSION_35, QUIC_VERSION_36,
                                    QUIC_VERSION_37, QUIC_VERSION_38,
                                    QUIC_VERSION_39};

  FLAGS_quic_reloadable_flag_quic_enable_version_38 = true;
  FLAGS_quic_reloadable_flag_quic_enable_version_39 = true;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(all_versions, filtered_versions);
}

TEST_F(QuicVersionsTest, LookUpVersionByIndex) {
  QuicVersionVector all_versions = {QUIC_VERSION_35, QUIC_VERSION_36,
                                    QUIC_VERSION_37, QUIC_VERSION_38,
                                    QUIC_VERSION_39};
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
