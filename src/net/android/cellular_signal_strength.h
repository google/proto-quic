// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_ANDROID_CELLULAR_SIGNAL_STRENGTH_H_
#define NET_ANDROID_CELLULAR_SIGNAL_STRENGTH_H_

#include <jni.h>
#include <stdint.h>

#include "base/compiler_specific.h"
#include "net/base/net_export.h"

namespace net {

namespace android {

namespace cellular_signal_strength {

// Returns true if the signal strength (in dbM) of the currently registered
// cellular connection is available, and sets |*signal_strength_dbm| to that
// value.
NET_EXPORT bool GetSignalStrengthDbm(int32_t* signal_strength_dbm)
    WARN_UNUSED_RESULT;

// Returns true if the signal strength level (between 0 and 4, both inclusive)
// of the currently registered cellular connection is available, and sets
// |*signal_strength_level| to that value with lower value indicating lower
// signal strength.
NET_EXPORT bool GetSignalStrengthLevel(int32_t* signal_strength_level)
    WARN_UNUSED_RESULT;

}  // namespace cellular_signal_strength

}  // namespace android

}  // namespace net

#endif  // NET_ANDROID_CELLULAR_SIGNAL_STRENGTH_H_
