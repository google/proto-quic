// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CHROMIUM_NETWORK_CONNECTION_H_
#define NET_QUIC_CHROMIUM_NETWORK_CONNECTION_H_

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/base/network_change_notifier.h"

namespace net {

// This class stores information about the current network type and
// provides a textual description of it.
class NET_EXPORT NetworkConnection
    : public NetworkChangeNotifier::IPAddressObserver,
      public NetworkChangeNotifier::ConnectionTypeObserver {
 public:
  NetworkConnection();
  ~NetworkConnection() override;

  // Returns the underlying connection type.
  NetworkChangeNotifier::ConnectionType connection_type() {
    return connection_type_;
  }

  // Return a string equivalent of current connection type. Callers don't need
  // to make a copy of the returned C-string value. If the connection type is
  // CONNECTION_WIFI, then we'll tease out some details when we are on WiFi, and
  // hopefully leave only ethernet (with no WiFi available) in the
  // CONNECTION_UNKNOWN category.  This *might* err if there is both ethernet,
  // as well as WiFi, where WiFi was not being used that much. Most platforms
  // don't distinguish Wifi vs Etherenet, and call everything CONNECTION_UNKNOWN
  // :-(. Fo non CONNECTIION_WIFI, this returns the C-string returned by
  // NetworkChangeNotifier::ConnectionTypeToString.
  const char* connection_description() { return connection_description_; }

  // NetworkChangeNotifier::IPAddressObserver methods:
  void OnIPAddressChanged() override;

  // NetworkChangeNotifier::ConnectionTypeObserver methods:
  void OnConnectionTypeChanged(
      NetworkChangeNotifier::ConnectionType type) override;

 private:
  // Cache the connection type to avoid calling the potentially expensive
  // NetworkChangeNotifier::GetConnectionType() function.
  NetworkChangeNotifier::ConnectionType connection_type_;
  // Cache the connection description string to avoid calling the expensive
  // GetWifiPHYLayerProtocol() function.
  const char* connection_description_;

  DISALLOW_COPY_AND_ASSIGN(NetworkConnection);
};

}  // namespace net

#endif  // NET_QUIC_CHROMIUM_NETWORK_CONNECTION_H_
