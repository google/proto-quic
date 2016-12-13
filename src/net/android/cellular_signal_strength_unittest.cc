// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/android/cellular_signal_strength.h"

#include <stdint.h>

#include "net/base/network_change_notifier.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(CellularSignalStrengthAndroidTest, SignalStrengthTest) {
  int signal_strength_dbm = INT32_MIN;
  bool signal_strength_available =
      android::cellular_signal_strength::GetSignalStrengthDbm(
          &signal_strength_dbm);

  // Signal strength is unavailable if the device does not have an active
  // cellular connection.
  if (!NetworkChangeNotifier::IsConnectionCellular(
          NetworkChangeNotifier::GetConnectionType())) {
    return;
  }

  EXPECT_TRUE(signal_strength_available);
  // Signal strength (in dbM) should typically be between -130 and 0.
  EXPECT_LE(-130, signal_strength_dbm);
  EXPECT_GE(0, signal_strength_dbm);
}

TEST(CellularSignalStrengthAndroidTest, SignalStrengthLevelTest) {
  int signal_strength_level = INT32_MIN;
  bool signal_strength_level_available =
      android::cellular_signal_strength::GetSignalStrengthLevel(
          &signal_strength_level);

  // Signal strength is unavailable if the device does not have an active
  // cellular connection.
  if (!NetworkChangeNotifier::IsConnectionCellular(
          NetworkChangeNotifier::GetConnectionType())) {
    return;
  }

  EXPECT_TRUE(signal_strength_level_available);
  EXPECT_LE(0, signal_strength_level);
  EXPECT_GE(4, signal_strength_level);
}

}  // namespace

}  // namespace net
