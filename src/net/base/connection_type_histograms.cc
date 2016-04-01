// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/connection_type_histograms.h"

#include "base/metrics/histogram_macros.h"

namespace net {

// We're using a histogram as a group of counters.  We're only interested in
// the values of the counters.  Ignore the shape, average, and standard
// deviation of the histograms because they are meaningless.
//
// We use two groups of counters.  In the first group (counter1), each counter
// is a boolean (0 or 1) that indicates whether the user has seen a connection
// of that type during that session.  In the second group (counter2), each
// counter is the number of connections of that type the user has seen during
// that session.
//
// Each histogram has an unused bucket at the end to allow seamless future
// expansion.
void UpdateConnectionTypeHistograms(ConnectionType type) {
  // TODO(wtc): Bug 74467 Move these stats up to a higher level.
  static bool had_connection_type[NUM_OF_CONNECTION_TYPES];  // Default false.

  if (type >= 0 && type < NUM_OF_CONNECTION_TYPES) {
    if (!had_connection_type[type]) {
      had_connection_type[type] = true;
      UMA_HISTOGRAM_ENUMERATION("Net.HadConnectionType3",
          type, NUM_OF_CONNECTION_TYPES);
    }

    UMA_HISTOGRAM_ENUMERATION("Net.ConnectionTypeCount3",
        type, NUM_OF_CONNECTION_TYPES);
  } else {
    NOTREACHED();  // Someone's logging an invalid type!
  }
}

}  // namespace net
