// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "traceimpl_overloaded_error.h"

namespace blink {

void ExternBase::trace(Visitor* visitor) {
  // Missing visitor->trace(x_base_).
}

void ExternDerived::trace(Visitor* visitor) {
  // Missing visitor->trace(x_derived_) and ExternBase::trace(visitor).
}

}
