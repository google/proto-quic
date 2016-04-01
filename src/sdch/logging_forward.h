// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SDCH_LOGGING_FORWARD_H_
#define SDCH_LOGGING_FORWARD_H_

// Define open-vcdiff's logging.h header guard, so that it doesn't get used.
#define OPEN_VCDIFF_LOGGING_H_

#include "base/logging.h"

// open-vcdiff's logging.h includes iostream, which adds static initializers
// to several compilation units. To prevent this, provide this replacement
// header which forwards open-vcdiffs logging macros to chromium's base logging
// mechanism.
#define VCD_WARNING LOG(WARNING)
#define VCD_ERROR LOG(ERROR)
#define VCD_DFATAL LOG(DFATAL)
#define VCD_ENDL "\n"

#endif  // SDCH_LOGGING_FORWARD_H_
