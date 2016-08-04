// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_multipath_transmissions_map.h"

namespace net {

QuicMultipathTransmissionsMap::QuicMultipathTransmissionsMap() {}

QuicMultipathTransmissionsMap::~QuicMultipathTransmissionsMap() {
  for (std::pair<QuicPathIdPacketNumber, MultipathTransmissionsList*>
           packet_transmissions : transmission_map_) {
    packet_transmissions.second->pop_front();
    if (packet_transmissions.second->empty()) {
      delete packet_transmissions.second;
    }
  }
}

void QuicMultipathTransmissionsMap::OnPacketRetransmittedOnDifferentPath(
    QuicPathIdPacketNumber original_path_id_packet_number,
    QuicPathIdPacketNumber path_id_packet_number) {
  MultipathTransmissionsList* across_paths_transmission_list = nullptr;
  MultipathTransmissionsMap::iterator it =
      transmission_map_.find(original_path_id_packet_number);
  if (it != transmission_map_.end()) {
    across_paths_transmission_list = it->second;
  } else {
    across_paths_transmission_list = new MultipathTransmissionsList();
    across_paths_transmission_list->push_back(original_path_id_packet_number);
    transmission_map_[original_path_id_packet_number] =
        across_paths_transmission_list;
  }

  across_paths_transmission_list->push_back(path_id_packet_number);
  transmission_map_[path_id_packet_number] = across_paths_transmission_list;
}

const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
QuicMultipathTransmissionsMap::MaybeGetTransmissionsOnOtherPaths(
    QuicPathIdPacketNumber path_id_packet_number) const {
  MultipathTransmissionsMap::const_iterator it =
      transmission_map_.find(path_id_packet_number);
  if (it == transmission_map_.end()) {
    return nullptr;
  }

  return it->second;
}

void QuicMultipathTransmissionsMap::OnPacketHandled(
    QuicPathIdPacketNumber path_id_packet_number) {
  MultipathTransmissionsMap::iterator it =
      transmission_map_.find(path_id_packet_number);
  if (it == transmission_map_.end()) {
    return;
  }

  MultipathTransmissionsList* transmission_list = it->second;
  MultipathTransmissionsList::iterator transmission_it;
  // Remove all across paths transmissions of this packet from the map.
  for (QuicPathIdPacketNumber path_id_packet_number : *transmission_list) {
    transmission_map_.erase(path_id_packet_number);
  }
  // Remove the multipath transmissions list.
  delete transmission_list;
}

}  // namespace net
