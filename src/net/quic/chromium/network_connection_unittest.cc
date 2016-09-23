// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/network_connection.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

class NetworkConnectionPeer {
 public:
  static NetworkChangeNotifier::ConnectionType connection_type(
      const NetworkConnection& network_connection) {
    return network_connection.connection_type_;
  }
  static void set_connection_type(NetworkConnection* network_connection,
                                  NetworkChangeNotifier::ConnectionType type) {
    network_connection->connection_type_ = type;
  }

  static const char* connection_description(
      const NetworkConnection& network_connection) {
    return network_connection.connection_description_;
  }
  static void set_connection_description(NetworkConnection* network_connection,
                                         const char* description) {
    network_connection->connection_description_ = description;
  }
};

// Test NetworkConnection().
class NetworkConnectionTest : public testing::Test {
 protected:
  void CheckNetworkConnectionDescription() {
    NetworkChangeNotifier::ConnectionType type =
        NetworkChangeNotifier::GetConnectionType();
    const char* description = network_connection_.GetDescription();
    // Verify GetDescription() updated the cached data.
    EXPECT_EQ(NetworkConnectionPeer::connection_type(network_connection_),
              type);
    EXPECT_EQ(
        NetworkConnectionPeer::connection_description(network_connection_),
        description);

    if (type != NetworkChangeNotifier::CONNECTION_WIFI)
      EXPECT_EQ(description,
                NetworkChangeNotifier::ConnectionTypeToString(type));
    else
      EXPECT_NE(nullptr, network_connection_.GetDescription());
  }

  NetworkConnection network_connection_;
};

TEST_F(NetworkConnectionTest, GetDescription) {
  const char* description = network_connection_.GetDescription();

  // Set connection description to nullptr.
  NetworkConnectionPeer::set_connection_description(&network_connection_,
                                                    nullptr);
  CheckNetworkConnectionDescription();

  // Set connection type to a junk value.
  NetworkConnectionPeer::set_connection_type(
      &network_connection_, NetworkChangeNotifier::CONNECTION_LAST);
  CheckNetworkConnectionDescription();

  EXPECT_EQ(description, network_connection_.GetDescription());
}

TEST_F(NetworkConnectionTest, Clear) {
  CheckNetworkConnectionDescription();
  network_connection_.Clear();
  CheckNetworkConnectionDescription();
}

}  // namespace test
}  // namespace net
