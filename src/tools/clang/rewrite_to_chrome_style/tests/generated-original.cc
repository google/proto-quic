// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/thing.h"

namespace blink {
void nonGenThing();
}

void G() {
  // Generated names should not attempt to be changed.
  blink::genThing();
  // Non-generated names should though.
  blink::nonGenThing();
}
