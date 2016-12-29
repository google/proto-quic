// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "class_multiple_trace_bases.h"

namespace blink {

void Base::Trace(Visitor* visitor) { }

void Mixin1::Trace(Visitor* visitor) { }

void Mixin2::Trace(Visitor* visitor) { }

// Missing: void Derived1::Trace(Visitor* visitor);

void Derived2::Trace(Visitor* visitor) {
    Base::Trace(visitor);
    Mixin1::Trace(visitor);
}

}
