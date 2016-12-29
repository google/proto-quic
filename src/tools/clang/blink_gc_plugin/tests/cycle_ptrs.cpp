// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cycle_ptrs.h"

namespace blink {

void A::Trace(Visitor* visitor) {
    visitor->Trace(m_b);
}

void B::Trace(Visitor* visitor) {
    visitor->Trace(m_a);
}

}
