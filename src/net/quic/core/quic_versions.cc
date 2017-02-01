// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_versions.h"

#include "base/strings/string_piece.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_tag.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_logging.h"

using base::StringPiece;
using std::string;

namespace net {

QuicVersionVector AllSupportedVersions() {
  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }
  return supported_versions;
}

QuicVersionVector CurrentSupportedVersions() {
  return FilterSupportedVersions(AllSupportedVersions());
}

QuicVersionVector FilterSupportedVersions(QuicVersionVector versions) {
  QuicVersionVector filtered_versions(versions.size());
  filtered_versions.clear();  // Guaranteed by spec not to change capacity.
  for (QuicVersion version : versions) {
    if (version == QUIC_VERSION_38) {
      if (FLAGS_quic_enable_version_38 &&
          FLAGS_quic_reloadable_flag_quic_enable_version_37 &&
          FLAGS_quic_reloadable_flag_quic_enable_version_36_v3) {
        filtered_versions.push_back(version);
      }
    } else if (version == QUIC_VERSION_37) {
      if (FLAGS_quic_reloadable_flag_quic_enable_version_37 &&
          FLAGS_quic_reloadable_flag_quic_enable_version_36_v3) {
        filtered_versions.push_back(version);
      }
    } else if (version == QUIC_VERSION_36) {
      if (FLAGS_quic_reloadable_flag_quic_enable_version_36_v3) {
        filtered_versions.push_back(version);
      }
    } else if (version == QUIC_VERSION_34) {
      if (!FLAGS_quic_reloadable_flag_quic_disable_version_34) {
        filtered_versions.push_back(version);
      }
    } else {
      filtered_versions.push_back(version);
    }
  }
  return filtered_versions;
}

QuicVersionVector VersionOfIndex(const QuicVersionVector& versions, int index) {
  QuicVersionVector version;
  int version_count = versions.size();
  if (index >= 0 && index < version_count) {
    version.push_back(versions[index]);
  } else {
    version.push_back(QUIC_VERSION_UNSUPPORTED);
  }
  return version;
}

QuicTag QuicVersionToQuicTag(const QuicVersion version) {
  switch (version) {
    case QUIC_VERSION_34:
      return MakeQuicTag('Q', '0', '3', '4');
    case QUIC_VERSION_35:
      return MakeQuicTag('Q', '0', '3', '5');
    case QUIC_VERSION_36:
      return MakeQuicTag('Q', '0', '3', '6');
    case QUIC_VERSION_37:
      return MakeQuicTag('Q', '0', '3', '7');
    case QUIC_VERSION_38:
      return MakeQuicTag('Q', '0', '3', '8');
    default:
      // This shold be an ERROR because we should never attempt to convert an
      // invalid QuicVersion to be written to the wire.
      QUIC_LOG(ERROR) << "Unsupported QuicVersion: " << version;
      return 0;
  }
}

QuicVersion QuicTagToQuicVersion(const QuicTag version_tag) {
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    if (version_tag == QuicVersionToQuicTag(kSupportedQuicVersions[i])) {
      return kSupportedQuicVersions[i];
    }
  }
  // Reading from the client so this should not be considered an ERROR.
  QUIC_DLOG(INFO) << "Unsupported QuicTag version: "
                  << QuicTagToString(version_tag);
  return QUIC_VERSION_UNSUPPORTED;
}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x

string QuicVersionToString(const QuicVersion version) {
  switch (version) {
    RETURN_STRING_LITERAL(QUIC_VERSION_34);
    RETURN_STRING_LITERAL(QUIC_VERSION_35);
    RETURN_STRING_LITERAL(QUIC_VERSION_36);
    RETURN_STRING_LITERAL(QUIC_VERSION_37);
    RETURN_STRING_LITERAL(QUIC_VERSION_38);
    default:
      return "QUIC_VERSION_UNSUPPORTED";
  }
}

string QuicVersionVectorToString(const QuicVersionVector& versions) {
  string result = "";
  for (size_t i = 0; i < versions.size(); ++i) {
    if (i != 0) {
      result.append(",");
    }
    result.append(QuicVersionToString(versions[i]));
  }
  return result;
}

}  // namespace net
