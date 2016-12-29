// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cycle_super.h"

namespace blink {

void A::Trace(Visitor* visitor) {
    visitor->Trace(m_d);
}

void B::Trace(Visitor* visitor) {
    A::Trace(visitor);
}

void C::Trace(Visitor* visitor) {
    B::Trace(visitor);
}

}
