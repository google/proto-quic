// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/network_connection.h"

#include "net/base/network_interfaces.h"

namespace net {

NetworkConnection::NetworkConnection()
    : connection_type_(NetworkChangeNotifier::CONNECTION_UNKNOWN),
      connection_description_(nullptr) {}

const char* NetworkConnection::GetDescription() {
  NetworkChangeNotifier::ConnectionType type =
      NetworkChangeNotifier::GetConnectionType();
  if (connection_description_ != nullptr && type == connection_type_)
    return connection_description_;

  DVLOG(1) << "Updating NetworkConnection's Cached Data";

  connection_description_ = NetworkChangeNotifier::ConnectionTypeToString(type);
  connection_type_ = type;
  if (connection_type_ == NetworkChangeNotifier::CONNECTION_UNKNOWN ||
      connection_type_ == NetworkChangeNotifier::CONNECTION_WIFI) {
    // This function only seems usefully defined on Windows currently.
    WifiPHYLayerProtocol wifi_type = GetWifiPHYLayerProtocol();
    switch (wifi_type) {
      case WIFI_PHY_LAYER_PROTOCOL_NONE:
        // No wifi support or no associated AP.
        break;
      case WIFI_PHY_LAYER_PROTOCOL_ANCIENT:
        // An obsolete modes introduced by the original 802.11, e.g. IR, FHSS.
        connection_description_ = "CONNECTION_WIFI_ANCIENT";
        break;
      case WIFI_PHY_LAYER_PROTOCOL_A:
        // 802.11a, OFDM-based rates.
        connection_description_ = "CONNECTION_WIFI_802.11a";
        break;
      case WIFI_PHY_LAYER_PROTOCOL_B:
        // 802.11b, DSSS or HR DSSS.
        connection_description_ = "CONNECTION_WIFI_802.11b";
        break;
      case WIFI_PHY_LAYER_PROTOCOL_G:
        // 802.11g, same rates as 802.11a but compatible with 802.11b.
        connection_description_ = "CONNECTION_WIFI_802.11g";
        break;
      case WIFI_PHY_LAYER_PROTOCOL_N:
        // 802.11n, HT rates.
        connection_description_ = "CONNECTION_WIFI_802.11n";
        break;
      case WIFI_PHY_LAYER_PROTOCOL_UNKNOWN:
        // Unclassified mode or failure to identify.
        break;
    }
  }
  return connection_description_;
}

void NetworkConnection::Clear() {
  connection_type_ = NetworkChangeNotifier::CONNECTION_UNKNOWN;
  connection_description_ = nullptr;
}

void NetworkConnection::OnIPAddressChanged() {
  Clear();
}

void NetworkConnection::OnConnectionTypeChanged(
    NetworkChangeNotifier::ConnectionType type) {
  Clear();
}

}  // namespace net
