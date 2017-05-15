// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_VERSIONS_H_
#define NET_QUIC_CORE_QUIC_VERSIONS_H_

#include <string>
#include <vector>

#include "net/quic/core/quic_tag.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

// The available versions of QUIC. Guaranteed that the integer value of the enum
// will match the version number.
// When adding a new version to this enum you should add it to
// kSupportedQuicVersions (if appropriate), and also add a new case to the
// helper methods QuicVersionToQuicTag, QuicTagToQuicVersion, and
// QuicVersionToString.
enum QuicVersion {
  // Special case to indicate unknown/unsupported QUIC version.
  QUIC_VERSION_UNSUPPORTED = 0,

  QUIC_VERSION_35 = 35,  // Allows endpoints to independently set stream limit.
  QUIC_VERSION_36 = 36,  // Add support to force HOL blocking.
  QUIC_VERSION_37 = 37,  // Add perspective into null encryption.
  QUIC_VERSION_38 = 38,  // PADDING frame is a 1-byte frame with type 0x00.
                         // Respect NSTP connection option.
  QUIC_VERSION_39 = 39,  // Integers and floating numbers are written in big
                         // endian. Dot not ack acks. Send a connection level
                         // WINDOW_UPDATE every 20 sent packets which do not
                         // contain retransmittable frames.
  QUIC_VERSION_40 = 40,  // Initial packet number is randomly chosen from
                         // [0:2^31], WINDOW_UPDATE for connection flow control
                         // advertises value in 1024-byte units, WINDOW_UPDATE
                         // splits into MAX_DATA and MAX_STREAM_DATA, BLOCKED
                         // frame split into BLOCKED and STREAM_BLOCKED frames

  // IMPORTANT: if you are adding to this list, follow the instructions at
  // http://sites/quic/adding-and-removing-versions
};

// This vector contains QUIC versions which we currently support.
// This should be ordered such that the highest supported version is the first
// element, with subsequent elements in descending order (versions can be
// skipped as necessary).
//
// IMPORTANT: if you are adding to this list, follow the instructions at
// http://sites/quic/adding-and-removing-versions
static const QuicVersion kSupportedQuicVersions[] = {
    QUIC_VERSION_40, QUIC_VERSION_39, QUIC_VERSION_38,
    QUIC_VERSION_37, QUIC_VERSION_36, QUIC_VERSION_35};

typedef std::vector<QuicVersion> QuicVersionVector;

// Returns a vector of QUIC versions in kSupportedQuicVersions.
QUIC_EXPORT_PRIVATE QuicVersionVector AllSupportedVersions();

// Returns a vector of QUIC versions from kSupportedQuicVersions which exclude
// any versions which are disabled by flags.
QUIC_EXPORT_PRIVATE QuicVersionVector CurrentSupportedVersions();

// Returns a vector of QUIC versions from |versions| which exclude any versions
// which are disabled by flags.
QUIC_EXPORT_PRIVATE QuicVersionVector
FilterSupportedVersions(QuicVersionVector versions);

// Returns QUIC version of |index| in result of |versions|. Returns
// QUIC_VERSION_UNSUPPORTED if |index| is out of bounds.
QUIC_EXPORT_PRIVATE QuicVersionVector
VersionOfIndex(const QuicVersionVector& versions, int index);

// QuicTag is written to and read from the wire, but we prefer to use
// the more readable QuicVersion at other levels.
// Helper function which translates from a QuicVersion to a QuicTag. Returns 0
// if QuicVersion is unsupported.
QUIC_EXPORT_PRIVATE QuicTag QuicVersionToQuicTag(const QuicVersion version);

// Returns appropriate QuicVersion from a QuicTag.
// Returns QUIC_VERSION_UNSUPPORTED if version_tag cannot be understood.
QUIC_EXPORT_PRIVATE QuicVersion QuicTagToQuicVersion(const QuicTag version_tag);

// Helper function which translates from a QuicVersion to a string.
// Returns strings corresponding to enum names (e.g. QUIC_VERSION_6).
QUIC_EXPORT_PRIVATE std::string QuicVersionToString(const QuicVersion version);

// Returns comma separated list of string representations of QuicVersion enum
// values in the supplied |versions| vector.
QUIC_EXPORT_PRIVATE std::string QuicVersionVectorToString(
    const QuicVersionVector& versions);

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_VERSIONS_H_
