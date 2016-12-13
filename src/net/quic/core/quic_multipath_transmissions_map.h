// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A map manages packets which are transmitted across multiple paths.
// For example, a packet is originally transmitted on path 1 with packet number
// 1. Then this packet is retransmitted on path 2 with packet number 1. (1, 1)
// and (2, 1) are inserted into this map. Suppose (2, 1) is detected lost and
// gets retransmitted on path 2 with packet 2. (2, 2) will not be inserted
// because this transmission does not "across" path compared to (2, 1).

#ifndef NET_QUIC_CORE_QUIC_MULTIPATH_TRANSMISSIONS_MAP_H_
#define NET_QUIC_CORE_QUIC_MULTIPATH_TRANSMISSIONS_MAP_H_

#include <deque>
#include <unordered_map>

#include "base/macros.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

typedef std::pair<QuicPathId, QuicPacketNumber> QuicPathIdPacketNumber;

class QUIC_EXPORT_PRIVATE QuicMultipathTransmissionsMap {
 public:
  struct QuicPathIdPacketNumberHash {
    size_t operator()(std::pair<QuicPathId, QuicPacketNumber> value) const {
      return QuicUtils::PackPathIdAndPacketNumber(value.first, value.second);
    }
  };

  typedef std::deque<QuicPathIdPacketNumber> MultipathTransmissionsList;
  typedef std::unordered_map<QuicPathIdPacketNumber,
                             MultipathTransmissionsList*,
                             QuicPathIdPacketNumberHash>
      MultipathTransmissionsMap;

  QuicMultipathTransmissionsMap();
  ~QuicMultipathTransmissionsMap();

  // Called when a packet is retransmitted on a different path. Adds both
  // |original_path_id_packet_number| (if not exists) and
  // |path_id_packet_number| to |transmission_map_|.
  void OnPacketRetransmittedOnDifferentPath(
      QuicPathIdPacketNumber original_path_id_packet_number,
      QuicPathIdPacketNumber path_id_packet_number);

  // Returns all multipath transmissions list if |path_id_packet_number| has
  // been transmitted across multiple paths, nullptr otherwise.
  const MultipathTransmissionsList* MaybeGetTransmissionsOnOtherPaths(
      QuicPathIdPacketNumber path_id_packet_number) const;

  // Called after packet |path_id_packet_number| is received.
  // If |path_id_packet_number| has been transmitted across multiple paths,
  // clears all multipath transmissions list and removes each transmission from
  // |transmission_map_|, does nothing otherwise.
  void OnPacketHandled(QuicPathIdPacketNumber path_id_packet_number);

 private:
  // Keys of the map are QuicPathIdPacketNumber, and values are pointers to
  // lists of multipath transmissions of the same packet. For example, if a
  // packet has been transmitted as (1, 1) and (2, 1), two entries are added
  // to this map and both values point to the same list: {(1, 1), (2, 1)}.
  // The MultipathTransmissionsList is owned by the transmission which is
  // received first (on any path).
  MultipathTransmissionsMap transmission_map_;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_MULTIPATH_TRANSMISSIONS_MAP_H_
