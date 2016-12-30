// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "traceimpl_error.h"

namespace blink {

void TraceImplExternWithUntracedMember::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceImplExternWithUntracedMember::TraceImpl(
    VisitorDispatcher visitor) {
  // Should get a warning as well.
}

void TraceImplExternWithUntracedBase::Trace(Visitor* visitor) {
  TraceImpl(visitor);
}

template <typename VisitorDispatcher>
inline void TraceImplExternWithUntracedBase::TraceImpl(
    VisitorDispatcher visitor) {
  // Ditto.
}

}
