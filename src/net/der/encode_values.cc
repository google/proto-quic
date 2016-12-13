// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/der/encode_values.h"

#include "base/time/time.h"
#include "net/der/parse_values.h"

namespace net {

namespace der {

bool EncodeTimeAsGeneralizedTime(const base::Time& time,
                                 GeneralizedTime* generalized_time) {
  base::Time::Exploded exploded;
  time.UTCExplode(&exploded);
  if (!exploded.HasValidValues())
    return false;

  generalized_time->year = exploded.year;
  generalized_time->month = exploded.month;
  generalized_time->day = exploded.day_of_month;
  generalized_time->hours = exploded.hour;
  generalized_time->minutes = exploded.minute;
  generalized_time->seconds = exploded.second;
  return true;
}

}  // namespace der

}  // namespace net
