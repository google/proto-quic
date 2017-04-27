// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/android/cellular_signal_strength.h"

#include "jni/AndroidCellularSignalStrength_jni.h"

namespace net {

namespace android {

namespace cellular_signal_strength {

// GENERATED_JAVA_ENUM_PACKAGE: org.chromium.net
enum CellularSignalStrengthError {
  // Value returned by CellularSignalStrength APIs when a valid value is
  // unavailable. This value is same as INT32_MIN, but the following code uses
  // the explicit value of INT32_MIN so that the auto-generated Java enums work
  // correctly.
  ERROR_NOT_SUPPORTED = -2147483648,
};

static_assert(
    INT32_MIN == ERROR_NOT_SUPPORTED,
    "CellularSignalStrengthError.ERROR_NOT_SUPPORTED has unexpected value");

bool GetSignalStrengthDbm(int32_t* signal_strength_dbm) {
  int32_t signal_strength_dbm_tmp =
      Java_AndroidCellularSignalStrength_getSignalStrengthDbm(
          base::android::AttachCurrentThread());
  if (signal_strength_dbm_tmp == ERROR_NOT_SUPPORTED)
    return false;

  *signal_strength_dbm = signal_strength_dbm_tmp;
  return true;
}

bool GetSignalStrengthLevel(int32_t* signal_strength_level) {
  int32_t signal_strength_level_tmp =
      Java_AndroidCellularSignalStrength_getSignalStrengthLevel(
          base::android::AttachCurrentThread());
  if (signal_strength_level_tmp == ERROR_NOT_SUPPORTED)
    return false;

  *signal_strength_level = signal_strength_level_tmp;
  return true;
}

}  // namespace cellular_signal_strength

}  // namespace android

}  // namespace net
