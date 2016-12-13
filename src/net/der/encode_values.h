// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DER_ENCODE_VALUES_H_
#define NET_DER_ENCODE_VALUES_H_

#include "net/base/net_export.h"

namespace base {
class Time;
}

namespace net {

namespace der {

struct GeneralizedTime;

// Encodes |time|, a UTC-based time, to DER |generalized_time|, for comparing
// against other GeneralizedTime objects.
NET_EXPORT bool EncodeTimeAsGeneralizedTime(const base::Time& time,
                                            GeneralizedTime* generalized_time);

}  // namespace der

}  // namespace net

#endif  // NET_DER_ENCODE_VALUES_H_
